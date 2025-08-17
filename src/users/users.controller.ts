import {
  Controller,
  Get,
  Patch,
  Delete,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  Logger,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { UsersService, UserProfile, UserStats } from './users.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { GetUser } from 'src/auth/decorators/get-user.decorator';
import { UserPayload } from 'src/auth/auth.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { FileValidationInterceptor } from './interceptors/file.interceptor';

@Controller('users')
@UseGuards(JwtAuthGuard) // All user endpoints require authentication
export class UsersController {
  private readonly logger = new Logger(UsersController.name);

  constructor(private usersService: UsersService) {}

  @Get('profile')
  @HttpCode(HttpStatus.OK)
  async getProfile(@GetUser() user: UserPayload): Promise<UserProfile> {
    this.logger.log(`Profile request for user: ${user.sub}`);
    return this.usersService.getUserProfile(user.sub);
  }

  @Patch('profile')
  @HttpCode(HttpStatus.OK)
  async updateProfile(
    @GetUser() user: UserPayload,
    @Body() dto: UpdateProfileDto,
  ): Promise<{ user: UserProfile; message: string }> {
    this.logger.log(`Profile update request for user: ${user.sub}`);

    const updatedUser = await this.usersService.updateProfile(user.sub, dto);

    return {
      user: updatedUser,
      message: 'Profile updated successfully',
    };
  }

  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  async changePassword(
    @GetUser() user: UserPayload,
    @Body() dto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    this.logger.log(`Password change request for user: ${user.sub}`);

    await this.usersService.changePassword(user.sub, dto);

    return {
      message: 'Password changed successfully. Please login again.',
    };
  }

  @Get('stats')
  @HttpCode(HttpStatus.OK)
  async getUserStats(@GetUser() user: UserPayload): Promise<UserStats> {
    this.logger.log(`Stats request for user: ${user.sub}`);
    return this.usersService.getUserStats(user.sub);
  }

  @Delete('account')
  @HttpCode(HttpStatus.OK)
  async deleteAccount(
    @GetUser() user: UserPayload,
  ): Promise<{ message: string }> {
    this.logger.log(`Account deletion request for user: ${user.sub}`);

    await this.usersService.deleteAccount(user.sub);

    return {
      message: 'Account deactivated successfully',
    };
  }

  @Post('avatar')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(FileInterceptor('avatar'), FileValidationInterceptor)
  async uploadAvatar(
    @GetUser() user: UserPayload,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<{ avatarUrl: string; message: string }> {
    this.logger.log(`Avatar upload request for user: ${user.sub}`);

    const result = await this.usersService.uploadAvatar(user.sub, file);

    return {
      avatarUrl: result.avatarUrl,
      message: 'Avatar uploaded successfully',
    };
  }

  @Delete('avatar')
  @HttpCode(HttpStatus.OK)
  async removeAvatar(
    @GetUser() user: UserPayload,
  ): Promise<{ message: string }> {
    this.logger.log(`Avatar removal request for user: ${user.sub}`);

    await this.usersService.removeAvatar(user.sub);

    return {
      message: 'Avatar removed successfully',
    };
  }
}
