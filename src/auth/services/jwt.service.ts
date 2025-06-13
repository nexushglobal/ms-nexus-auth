// src/auth/services/jwt.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import { envs } from '../../config/envs';
import { JwtPayload } from '../interfaces/login-response.interface';

@Injectable()
export class JwtAuthService {
  constructor(private readonly jwtService: NestJwtService) {}

  generateTokens(payload: JwtPayload) {
    // Access Token - 1 hora
    const accessToken = this.jwtService.sign(payload, {
      secret: envs.JWT_SECRET,
      expiresIn: '1h',
    });

    // Refresh Token - 7 días
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
    // Crear payload limpio sin propiedades automáticas del JWT
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

  createCleanPayload(payload: JwtPayload): JwtPayload {
    // Crear payload limpio removiendo iat, exp y otras propiedades del JWT
    return {
      email: payload.email,
      sub: payload.sub,
      role: payload.role,
    };
  }
}
