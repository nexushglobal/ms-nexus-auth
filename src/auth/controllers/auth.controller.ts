import { Controller, Logger } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginDto } from '../dto/login.dto';
import { AuthService } from '../services/auth.service';
import { RefreshTokenDto } from '../dto/refresh-token.dto';

@Controller()
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @MessagePattern({ cmd: 'auth.login' })
  async login(@Payload() loginDto: LoginDto) {
    this.logger.log(`📥 Solicitud de login recibida para: ${loginDto.email}`);
    return await this.authService.login(loginDto);
  }

  @MessagePattern({ cmd: 'auth.refreshToken' })
  async refreshToken(@Payload() data: RefreshTokenDto) {
    this.logger.log('📥 Solicitud de refresh token recibida');
    return await this.authService.refreshToken(data.refreshToken);
  }

  @MessagePattern({ cmd: 'auth.verifyToken' })
  verifyToken(@Payload() data: { token: string }) {
    this.logger.log('📥 Solicitud de verificación de token recibida');
    try {
      const decoded = this.authService['jwtAuthService'].verifyAccessToken(
        data.token,
      );
      return {
        success: true,
        payload: decoded,
      };
    } catch (error) {
      return {
        success: false,
        message: error.message,
      };
    }
  }
}
