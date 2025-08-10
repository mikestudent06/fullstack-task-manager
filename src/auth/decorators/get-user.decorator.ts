import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserPayload } from '../auth.dto';

export const GetUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext): UserPayload | string | null => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      return null;
    }

    return data ? user[data] : user;
  },
);
