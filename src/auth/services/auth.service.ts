import { Injectable, Logger } from '@nestjs/common';
import {
  ClientProxy,
  ClientProxyFactory,
  RpcException,
  Transport,
} from '@nestjs/microservices';
import * as bcrypt from 'bcryptjs';
import { firstValueFrom } from 'rxjs';

import { envs } from '../../config/envs';
import { LoginDto } from '../dto/login.dto';
import {
  LoginResponse,
  ViewResponse,
} from '../interfaces/login-response.interface';
import { JwtAuthService } from './jwt.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly usersClient: ClientProxy;

  constructor(private readonly jwtAuthService: JwtAuthService) {
    this.usersClient = ClientProxyFactory.create({
      transport: Transport.NATS,
      options: {
        servers: [envs.NATS_SERVERS],
      },
    });
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    try {
      this.logger.log(`🔐 Intento de login para: ${loginDto.email}`);

      const userWithPassword = await firstValueFrom(
        this.usersClient.send(
          { cmd: 'user.findByEmailWithPassword' },
          { email: loginDto.email },
        ),
      );

      if (!userWithPassword) {
        throw new RpcException({
          status: 401,
          message: 'Credenciales inválidas',
        });
      }

      const isPasswordValid = await bcrypt.compare(
        loginDto.password,
        String(userWithPassword.password),
      );

      if (!isPasswordValid) {
        throw new RpcException({
          status: 401,
          message: 'Credenciales inválidas',
        });
      }

      const userWithRole = await firstValueFrom(
        this.usersClient.send(
          { cmd: 'user.findUserWithRoleById' },
          { id: userWithPassword.id },
        ),
      );

      if (!userWithRole || !userWithRole.isActive) {
        throw new RpcException({
          status: 401,
          message: 'Usuario inactivo o no encontrado',
        });
      }

      const viewsResponse = await firstValueFrom(
        this.usersClient.send(
          { cmd: 'user.view.getViewsByRoleId' },
          { roleId: userWithRole.role.id },
        ),
      );

      const views: ViewResponse[] = viewsResponse.success
        ? viewsResponse.views
        : [];

      await firstValueFrom(
        this.usersClient.send(
          { cmd: 'user.updateLastLoginAt' },
          { userId: userWithRole.id },
        ),
      );

      const payload = this.jwtAuthService.createPayload(userWithRole);
      const tokens = this.jwtAuthService.generateTokens(payload);

      const loginResponse: LoginResponse = {
        user: {
          id: userWithRole.id,
          email: userWithRole.email,
          photo: userWithRole.photo || null,
          nickname: userWithRole.nickname || null,
          firstName: userWithRole.personalInfo?.firstName || '',
          lastName: userWithRole.personalInfo?.lastName || '',
          role: {
            id: userWithRole.role.id,
            code: userWithRole.role.code,
            name: userWithRole.role.name,
          },
          views: this.formatViews(views),
        },
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };

      this.logger.log(`✅ Login exitoso para: ${loginDto.email}`);
      return loginResponse;
    } catch (error) {
      this.logger.error(`❌ Error en login para ${loginDto.email}:`, error);

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        status: 500,
        message: 'Error interno del servidor durante el login',
      });
    }
  }

  async refreshToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      const payload = this.jwtAuthService.verifyRefreshToken(refreshToken);

      const isUserActive = await firstValueFrom(
        this.usersClient.send(
          { cmd: 'user.validateUserExists' },
          { userId: payload.sub },
        ),
      );

      if (!isUserActive) {
        throw new RpcException({
          status: 401,
          message: 'Usuario no válido',
        });
      }

      const cleanPayload = this.jwtAuthService.createCleanPayload(payload);
      const newTokens = this.jwtAuthService.generateTokens(cleanPayload);

      this.logger.log(`🔄 Tokens renovados para usuario: ${payload.sub}`);
      return newTokens;
    } catch (error) {
      this.logger.error('❌ Error renovando tokens:', error);

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        status: 401,
        message: 'Token de refresh inválido',
      });
    }
  }

  private formatViews(views: any[]): ViewResponse[] {
    return views.map((view) => ({
      id: view.id,
      code: view.code,
      name: view.name,
      icon: view.icon || null,
      url: view.url || null,
      order: view.order,
      metadata: view.metadata || null,
      children: Array.isArray(view.children)
        ? this.formatViews(view.children as any[])
        : [],
    }));
  }

  async onModuleDestroy() {
    await this.usersClient.close();
  }
}
