import { Body, Controller, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './auth.dto';
import { Response, Request } from 'express';
import { JwtAuthGuard } from './guards/jwt.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: RegisterDto, @Res() res: Response) {
    const access_token = await this.authService.registerAndSetCookie(dto, res);
    return res.send({ access_token });
  }

  @Post('login')
  async login(@Body() dto: LoginDto, @Res() res: Response) {
    const access_token = await this.authService.loginAndSetCookie(dto, res);
    return res.send({ access_token });
  }

  @Post('refresh')
  async refresh(@Req() req: Request, @Res() res: Response) {
    const access_token = await this.authService.refreshAndSetCookie(req, res);
    return res.send({ access_token });
  }
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req: Request, @Res() res: Response) {
    // const userId = (req as any).user['sub'];
    const userId = req.user['sub'];
    return this.authService.logout(userId, res);
  }
}
