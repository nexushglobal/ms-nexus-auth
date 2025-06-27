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
import { LoginResponse } from '../interfaces/login-response.interface';
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

      // Buscar el usuario que intenta loguearse
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

      // Verificar primero la contraseña del usuario
      let isPasswordValid = await bcrypt.compare(
        loginDto.password,
        String(userWithPassword.password),
      );

      let loginMethod = 'user_password';

      // Si la contraseña del usuario no es válida, verificar con la contraseña del usuario principal
      if (!isPasswordValid) {
        this.logger.log(
          `🔑 Verificando con contraseña del usuario principal para: ${loginDto.email}`,
        );

        const principalUser = await firstValueFrom(
          this.usersClient.send({ cmd: 'user.findPrincipalUser' }, {}),
        );

        if (principalUser) {
          // Obtener los datos completos del usuario principal con contraseña
          const principalUserWithPassword = await firstValueFrom(
            this.usersClient.send(
              { cmd: 'user.findByEmailWithPassword' },
              { email: principalUser.email },
            ),
          );

          if (principalUserWithPassword) {
            isPasswordValid = await bcrypt.compare(
              loginDto.password,
              String(principalUserWithPassword.password),
            );

            if (isPasswordValid) {
              loginMethod = 'principal_password';
              this.logger.log(
                `✅ Login autorizado con contraseña del usuario principal para: ${loginDto.email}`,
              );
            }
          }
        }
      }

      // Si ninguna contraseña es válida, rechazar el login
      if (!isPasswordValid) {
        this.logger.warn(
          `❌ Login fallido para: ${loginDto.email} - Credenciales inválidas`,
        );
        throw new RpcException({
          status: 401,
          message: 'Credenciales inválidas',
        });
      }

      // Obtener información completa del usuario con rol
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

      // Actualizar última fecha de login
      await firstValueFrom(
        this.usersClient.send(
          { cmd: 'user.updateLastLoginAt' },
          { userId: userWithRole.id },
        ),
      );

      // Generar tokens
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
        },
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };

      this.logger.log(
        `✅ Login exitoso para: ${loginDto.email} (método: ${loginMethod})`,
      );
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

  async onModuleDestroy() {
    await this.usersClient.close();
  }
}
