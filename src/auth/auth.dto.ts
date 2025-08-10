import {
  IsEmail,
  IsNotEmpty,
  MinLength,
  Length,
  Matches,
  IsString,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class RegisterDto {
  @IsEmail({}, { message: 'Invalid email format' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @IsNotEmpty({ message: 'Name is required' })
  @Length(2, 50, { message: 'Name must be between 2 and 50 characters' })
  @Transform(({ value }) => value?.trim())
  name: string;

  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  password: string;
}

export class LoginDto {
  @IsEmail({}, { message: 'Invalid email format' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

export class TokenPair {
  access_token: string;
  refresh_token: string;
}

export interface AuthResponse {
  access_token: string;
  message: string;
}

export interface UserPayload {
  sub: string;
  email: string;
}

export class VerifyOtpDto {
  @IsString()
  @IsNotEmpty()
  @Length(6, 6) // Assuming 6-digit OTP
  otp: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;
}

export class ResendOtpDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
