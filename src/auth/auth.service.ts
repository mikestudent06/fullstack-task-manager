import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginDto, RegisterDto } from './auth.dto';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { Response, Request } from 'express';
import { setRefreshTokenCookie } from './utils/cookies.util';
import { verifyToken } from './utils/jwt.util';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async registerAndSetCookie(dto: RegisterDto, res: Response): Promise<string> {
    const userExists = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (userExists) {
      throw new ForbiddenException('Email already registered');
    }

    const hash = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        password: hash,
      },
    });

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    setRefreshTokenCookie(res, tokens.refresh_token);

    return tokens.access_token;
  }

  async loginAndSetCookie(dto: LoginDto, res: Response): Promise<string> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user || !(await bcrypt.compare(dto.password, user.password))) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    setRefreshTokenCookie(res, tokens.refresh_token);

    return tokens.access_token;
  }
  async logout(userId: string, res: Response): Promise<void> {
    // 🧹 Clear refresh token in DB
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
    // 🧹 Clear cookie
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/auth/refresh',
    });
  }

  async refreshAndSetCookie(req: Request, res: Response): Promise<string> {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token found');
    }

    const payload = verifyToken<{ sub: string; email: string }>(
      refreshToken,
      this.config.get('JWT_REFRESH_SECRET') as string,
      this.jwt,
    );

    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token structure');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    const tokenMatches = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!tokenMatches) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    setRefreshTokenCookie(res, tokens.refresh_token);

    return tokens.access_token;
  }

  async generateTokens(
    userId: string,
    email: string,
  ): Promise<{
    access_token: string;
    refresh_token: string;
  }> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwt.signAsync(
        { sub: userId, email },
        {
          secret: this.config.get('JWT_SECRET'),
          expiresIn: '15m',
        },
      ),
      this.jwt.signAsync(
        { sub: userId, email },
        {
          secret: this.config.get('JWT_REFRESH_SECRET'),
          expiresIn: '7d',
        },
      ),
    ]);

    return { access_token, refresh_token };
  }

  async updateRefreshToken(userId: string, token: string): Promise<void> {
    const hashed = await bcrypt.hash(token, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: hashed,
      },
    });
  }
}
