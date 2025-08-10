import { Response } from 'express';

const isProduction = process.env.NODE_ENV === 'production';

export function setRefreshTokenCookie(res: Response, refreshToken: string): void {
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: isProduction, // Only secure in production
    sameSite: isProduction ? 'strict' : 'lax', // Stricter in production
    path: '/auth/refresh',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
}

export function clearRefreshTokenCookie(res: Response): void {
  res.clearCookie('refresh_token', {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/auth/refresh',
  });
}