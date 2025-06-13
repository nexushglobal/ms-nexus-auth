import { Injectable } from '@nestjs/common';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import { envs } from '../../config/envs';
import { JwtPayload } from '../interfaces/login-response.interface';

@Injectable()
export class JwtAuthService {
  constructor(private readonly jwtService: NestJwtService) {}

  generateTokens(payload: JwtPayload) {
    const accessToken = this.jwtService.sign(payload, {
      secret: envs.JWT_SECRET,
      expiresIn: '1h',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: envs.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  verifyAccessToken(token: string): JwtPayload {
    try {
      return this.jwtService.verify(token, {
        secret: envs.JWT_SECRET,
      });
    } catch {
      throw new Error('Token de acceso inválido');
    }
  }

  verifyRefreshToken(token: string): JwtPayload {
    try {
      return this.jwtService.verify(token, {
        secret: envs.JWT_REFRESH_SECRET,
      });
    } catch {
      throw new Error('Token de refresh inválido');
    }
  }

  createPayload(user: any): JwtPayload {
    return {
      email: user.email,
      sub: user.id,
      role: {
        id: user.role.id,
        code: user.role.code,
        name: user.role.name,
      },
    };
  }
}
