import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import * as bcrypt from 'bcrypt';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  avatar: string | null;
  isVerified: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
}

export interface UserStats {
  accountAge: number; // days since registration
  lastLogin: Date | null;
  isVerified: boolean;
}

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private prisma: PrismaService,
    private cloudinaryService: CloudinaryService,
  ) {}

  async getUserProfile(userId: string): Promise<UserProfile> {
    this.logger.log(`Getting profile for user: ${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        avatar: true,
        isVerified: true,
        lastLoginAt: true,
        createdAt: true,
      },
    });

    if (!user) {
      this.logger.warn(`Profile request for non-existent user: ${userId}`);
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async updateProfile(
    userId: string,
    dto: UpdateProfileDto,
  ): Promise<UserProfile> {
    this.logger.log(`Updating profile for user: ${userId}`);

    // Check if user exists
    const existingUser = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!existingUser) {
      throw new NotFoundException('User not found');
    }

    // If updating email, check it's not already taken
    if (dto.email && dto.email !== existingUser.email) {
      const emailTaken = await this.prisma.user.findUnique({
        where: { email: dto.email },
      });

      if (emailTaken) {
        this.logger.warn(
          `Profile update failed - email already exists: ${dto.email}`,
        );
        throw new ForbiddenException('Email already in use');
      }
    }

    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: {
        ...(dto.name && { name: dto.name }),
        ...(dto.email && { email: dto.email }),
      },
      select: {
        id: true,
        email: true,
        name: true,
        avatar: true,
        isVerified: true,
        lastLoginAt: true,
        createdAt: true,
      },
    });

    this.logger.log(`Profile updated successfully for user: ${userId}`);
    return updatedUser;
  }

  async changePassword(userId: string, dto: ChangePasswordDto): Promise<void> {
    this.logger.log(`Password change request for user: ${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(
      dto.currentPassword,
      user.password,
    );

    if (!isCurrentPasswordValid) {
      this.logger.warn(
        `Password change failed - invalid current password for user: ${userId}`,
      );
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(dto.newPassword, 12);

    // Update password and clear refresh tokens (force re-login)
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        password: hashedNewPassword,
        refreshToken: null, // Force re-login on all devices
      },
    });

    this.logger.log(`Password changed successfully for user: ${userId}`);
  }

  async getUserStats(userId: string): Promise<UserStats> {
    this.logger.log(`Getting stats for user: ${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        createdAt: true,
        lastLoginAt: true,
        isVerified: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const accountAge = Math.floor(
      (Date.now() - user.createdAt.getTime()) / (1000 * 60 * 60 * 24),
    );

    return {
      accountAge,
      lastLogin: user.lastLoginAt,
      isVerified: user.isVerified,
    };
  }

  async deleteAccount(userId: string): Promise<void> {
    this.logger.log(`Account deletion request for user: ${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Soft delete - set isActive to false
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        isActive: false,
        refreshToken: null,
        // Clear sensitive data
        otp: null,
        otpExpires: null,
        resetToken: null,
        resetTokenExpires: null,
      },
    });

    this.logger.log(`Account deactivated for user: ${userId}`);
  }

  async uploadAvatar(
    userId: string,
    file: Express.Multer.File,
  ): Promise<{ avatarUrl: string }> {
    this.logger.log(`Avatar upload request for user: ${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, avatar: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Delete old avatar if exists
    if (user.avatar) {
      // Extract public_id from Cloudinary URL
      const urlParts = user.avatar.split('/');
      const publicIdWithExtension = urlParts[urlParts.length - 1];
      const publicId = `task-manager/avatars/${publicIdWithExtension.split('.')[0]}`;
      await this.cloudinaryService.deleteImage(publicId);
    }

    // Upload new avatar
    const uploadResult = await this.cloudinaryService.uploadImage(
      file,
      'avatars',
    );

    // Update user record
    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: { avatar: uploadResult.secure_url },
      select: { avatar: true },
    });

    this.logger.log(`Avatar uploaded successfully for user: ${userId}`);

    return { avatarUrl: updatedUser.avatar! };
  }

  async removeAvatar(userId: string): Promise<void> {
    this.logger.log(`Avatar removal request for user: ${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, avatar: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.avatar) {
      throw new BadRequestException('No avatar to remove');
    }

    // Delete from Cloudinary
    const urlParts = user.avatar.split('/');
    const publicIdWithExtension = urlParts[urlParts.length - 1];
    const publicId = `task-manager/avatars/${publicIdWithExtension.split('.')[0]}`;
    await this.cloudinaryService.deleteImage(publicId);

    // Update user record
    await this.prisma.user.update({
      where: { id: userId },
      data: { avatar: null },
    });

    this.logger.log(`Avatar removed successfully for user: ${userId}`);
  }
}
