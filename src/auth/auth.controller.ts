import {
  Body,
  Controller,
  Post,
  Req,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  LoginDto,
  RegisterDto,
  AuthResponse,
  UserPayload,
  VerifyOtpDto,
  ResendOtpDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from './auth.dto';
import { Response, Request } from 'express';
import { JwtAuthGuard } from './guards/jwt.guard';
import { ThrottlerGuard } from '@nestjs/throttler';
import {
  setRefreshTokenCookie,
  clearRefreshTokenCookie,
} from './utils/cookies.util';
import { GetUser } from './decorators/get-user.decorator';

@Controller('auth')
@UseGuards(ThrottlerGuard) // Rate limiting for all auth endpoints
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto): Promise<{ message: string }> {
    this.logger.log(`Registration request for email: ${dto.email}`);

    await this.authService.register(dto);

    // No tokens set here because user not verified yet
    return {
      message:
        'Registration successful. Please check your email for the OTP to verify your account.',
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponse> {
    this.logger.log(`Login request for email: ${dto.email}`);

    const tokens = await this.authService.login(dto);
    setRefreshTokenCookie(res, tokens.refresh_token);

    return {
      access_token: tokens.access_token,
      message: 'Login successful',
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponse> {
    const refreshToken = req.cookies?.refresh_token;

    const tokens = await this.authService.refresh(refreshToken);
    setRefreshTokenCookie(res, tokens.refresh_token);

    return {
      access_token: tokens.access_token,
      message: 'Token refreshed successfully',
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @GetUser() user: UserPayload,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    this.logger.log(`Logout request for user: ${user.sub}`);

    await this.authService.logout(user.sub);
    clearRefreshTokenCookie(res);

    return { message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('deactivate')
  @HttpCode(HttpStatus.OK)
  async deactivateAccount(
    @GetUser() user: UserPayload,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    this.logger.log(`Deactivation request for user: ${user.sub}`);

    await this.authService.deactivateAccount(user.sub);
    clearRefreshTokenCookie(res);

    return { message: 'Account deactivated successfully' };
  }

  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponse> {
    this.logger.log(`OTP verification request for email: ${dto.email}`);

    const tokens = await this.authService.verifyOtpAndLogin(dto.otp, dto.email);
    setRefreshTokenCookie(res, tokens.refresh_token);

    this.logger.log(`OTP verification successful for email: ${dto.email}`);

    return {
      access_token: tokens.access_token,
      message: 'Email verified and logged in successfully',
    };
  }

  @Post('resend-otp')
  @HttpCode(HttpStatus.OK)
  async resendOtp(@Body() dto: ResendOtpDto): Promise<{ message: string }> {
    this.logger.log(`Resend OTP request for email: ${dto.email}`);

    await this.authService.resendOtp(dto.email);

    return {
      message: 'OTP sent successfully. Please check your email.',
    };
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
  ): Promise<{ message: string }> {
    this.logger.log(`Forgot password request for email: ${dto.email}`);

    await this.authService.forgotPassword(dto.email);

    return {
      message:
        'If your email is registered, you will receive a password reset link.',
    };
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Body() dto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    this.logger.log(`Password reset attempt`);

    await this.authService.resetPassword(dto.resetToken, dto.newPassword);

    return {
      message:
        'Password reset successful. Please login with your new password.',
    };
  }
}
