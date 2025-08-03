// auth/utils/jwt.util.ts
import { ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

export function verifyToken<T extends object>(
  token: string,
  secret: string,
  jwtService: JwtService, // ✅ add this
): T {
  try {
    return jwtService.verify<T>(token, { secret });
  } catch {
    throw new ForbiddenException('Invalid or expired token');
  }
}

export function decodeToken<T>(token: string, jwtService: JwtService): T {
  return jwtService.decode(token);
}
