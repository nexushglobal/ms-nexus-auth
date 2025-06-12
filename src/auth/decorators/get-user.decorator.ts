import { createParamDecorator, ExecutionContext } from '@nestjs/common';
export const GetUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request: { user: { id: string; email: string } } = ctx
      .switchToHttp()
      .getRequest();
    return request.user;
  },
);
