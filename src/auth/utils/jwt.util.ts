import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

export function verifyToken<T extends object>(
  token: string,
  secret: string,
  jwtService: JwtService,
): T {
  try {
    return jwtService.verify<T>(token, { secret });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new UnauthorizedException('Token has expired');
    }
    if (error.name === 'JsonWebTokenError') {
      throw new UnauthorizedException('Invalid token');
    }
    throw new UnauthorizedException('Token verification failed');
  }
}

export function decodeToken<T>(token: string, jwtService: JwtService): T {
  try {
    return jwtService.decode(token) as T;
  } catch (error) {
    throw new UnauthorizedException('Invalid token format');
  }
}
