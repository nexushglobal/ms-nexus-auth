import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { compare } from 'bcryptjs';
import { envs } from 'src/config/envs';
import { MailService } from 'src/mail/mail.service';
import {
  Membership,
  MembershipStatus,
} from 'src/memberships/entities/membership.entity';
import { NotificationFactory } from 'src/notifications/factory/notification.factory';
import { Role } from 'src/user/entities/roles.entity';
import { Ubigeo } from 'src/user/entities/ubigeo.entity';
import { User } from 'src/user/entities/user.entity';
import { View } from 'src/user/entities/view.entity';
import { UserService } from 'src/user/services/user.service';
import { DataSource, Repository } from 'typeorm';
import { RegisterDto } from '../dto/create-user.dto';
export interface CleanView {
  id: number;
  code: string;
  name: string;
  icon?: string | null;
  url?: string | null;
  order: number;
  metadata?: any | null;
  children: CleanView[];
}

export interface MembershipInfo {
  hasMembership: boolean;
  plan?: {
    id: number;
    name: string;
  };
  status?: string;
}
@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS = 10;
  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    @InjectRepository(View)
    private viewRepository: Repository<View>,
    private readonly dataSource: DataSource,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Ubigeo)
    private readonly ubigeoRepository: Repository<Ubigeo>,
    @InjectRepository(Membership)
    private membershipRepository: Repository<Membership>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    private readonly mailService: MailService,
    private readonly notificationFactory: NotificationFactory,
  ) {}
  private cleanView(view: View): CleanView {
    const {
      id,
      code,
      name,
      icon,
      url,
      order,
      metadata,
      children: rawChildren,
    } = view;
    const children =
      rawChildren
        ?.filter((child) => child.isActive)
        .map((child) => this.cleanView(child))
        .sort((a, b) => (a.order || 0) - (b.order || 0)) || [];
    return {
      id,
      code,
      name,
      icon,
      url,
      order: order || 0,
      metadata,
      children,
    };
  }

  private async buildViewTree(views: View[]): Promise<CleanView[]> {
    // const parentViews = views
    //   .filter((view) => !view.parent && view.isActive)
    //   .sort((a, b) => (a.order || 0) - (b.order || 0));
    // return parentViews.map((view) => this.cleanView(view));
    //TODO: REALIZAR LA FUNCIONALIDAD DE OBTENER EL ARBOL DE VIEWS EN EL MICROSERVICIO USER
  }

  private async getUserMembershipInfo(userId: string): Promise<MembershipInfo> {
    const membership = await this.membershipRepository.findOne({
      where: {
        user: { id: userId },
        status: MembershipStatus.ACTIVE,
      },
      relations: ['plan'],
    });

    if (!membership) {
      return { hasMembership: false };
    }

    return {
      hasMembership: true,
      plan: {
        id: membership.plan.id,
        name: membership.plan.name,
      },
      status: membership.status,
    };
  }

  async validateUser(email: string, password: string): Promise<any> {
    // const user = await this.usersService.findByEmail(email);
    //TODO: REMPLAZAR CON EL USO DE LA CMD 'user.findByEmail'
    // if (!user) return null;

    // const principalUser = await this.userRepository.findOne({
    //   where: { parent: IsNull(), role: { code: 'CLI' } },
    //   select: ['id', 'password', 'parent', 'role'],
    // });
    //TODO: CREAR UNA FUNCIONALIDAD PARA OBTENER EL USUARIO PRINCIPAL EN EL MICROSERVICIO USER

    const isPasswordUser = await compare(password, user.password);
    const isPasswordPrincipalUser = principalUser
      ? await compare(password, principalUser.password)
      : false;

    if (isPasswordUser || isPasswordPrincipalUser) {
      if (!user.role.isActive)
        throw new UnauthorizedException('El rol asociado está inactivo');
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const userWithRole = await this.usersService.findOne(user.id);
    if (!userWithRole.role.isActive) {
      throw new UnauthorizedException('El rol asociado está inactivo');
    }

    const roleViews = await this.viewRepository
      .createQueryBuilder('view')
      .leftJoinAndSelect('view.parent', 'parent')
      .leftJoinAndSelect('view.children', 'children')
      .leftJoin('view.roles', 'role')
      .where('role.id = :roleId', { roleId: userWithRole.role.id })
      .getMany();

    const viewTree = await this.buildViewTree(roleViews);

    const cleanRole = {
      id: userWithRole.role.id,
      code: userWithRole.role.code,
      name: userWithRole.role.name,
    };

    const payload = {
      email: user.email,
      sub: user.id,
      role: cleanRole,
    };

    // Fetch user's personal info to get firstName and lastName
    const userWithPersonalInfo = await this.userRepository.findOne({
      where: { id: user.id },
      relations: ['personalInfo'],
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        photo: user.photo,
        nickname: user.nickname,
        firstName: userWithPersonalInfo?.personalInfo?.firstName,
        lastName: userWithPersonalInfo?.personalInfo?.lastName,
        role: cleanRole,
        views: viewTree,
      },
      accessToken: this.jwtService.sign(payload),
      refreshToken: this.jwtService.sign(payload, {
        secret: envs.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      }),
    };
  }
  async refreshToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: envs.JWT_REFRESH_SECRET,
      });
      const user = await this.usersService.findOne(payload.sub);
      if (!user || !user.isActive || !user.role.isActive) {
        throw new UnauthorizedException();
      }
      return this.login(user);
    } catch {
      throw new UnauthorizedException();
    }
  }

  async register(registerDto: RegisterDto) {
    console.log('Registering user:', registerDto);
    //TODO: LLAMAR A LA cmd: 'user.register'

    try {
      // await this.sendWelcomeEmail(
      //   savedUser.email,
      //   personalInfo.firstName,
      //   personalInfo.lastName,
      // );

      const payload = {
        // email: savedUser.email,
        // sub: savedUser.id,
        // role: {
        //   id: role.id,
        //   code: role.code,
        //   name: role.name,
        // },
      };

      return {
        user: {
          // id: savedUser.id,
          // email: savedUser.email,
          // referralCode: savedUser.referralCode,
          // firstName: personalInfo.firstName,
          // lastName: personalInfo.lastName,
        },
        accessToken: this.jwtService.sign(payload),
        refreshToken: this.jwtService.sign(payload, {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: '7d',
        }),
      };
    } catch (error) {
      // await queryRunner.rollbackTransaction();

      if (
        error instanceof ConflictException ||
        error instanceof NotFoundException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      throw new InternalServerErrorException('Error al registrar el usuario');
    } finally {
      // await queryRunner.release();
    }
  }

  private async sendWelcomeEmail(
    email: string,
    firstName: string,
    lastName: string,
  ) {
    //TODO: LLAMAR AL MICROSERVICIO INTEGRATION MAIL
    await this.mailService.sendMail({
      to: email,
      subject: '¡Bienvenido a Nexus Platform!',
      html: `
        <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border-radius: 8px; border: 1px solid #ddd;">
          <div style="background-color: #0a8043; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 24px;">¡Bienvenido a Nexus Platform!</h1>
          </div>
          <div style="padding: 20px; background-color: #fff; border-radius: 0 0 8px 8px;">
            <p style="font-size: 16px; line-height: 1.6;">Hola <strong>${firstName} ${lastName}</strong>,</p>
            <p style="font-size: 16px; line-height: 1.6;">¡Gracias por unirte a nuestra plataforma! Estamos muy contentos de tenerte como miembro de nuestra comunidad.</p>
            <p style="font-size: 16px; line-height: 1.6;">Con tu cuenta de Nexus Platform podrás:</p>
            <ul style="font-size: 16px; line-height: 1.6;">
              <li>Acceder a planes de membresía exclusivos</li>
              <li>Construir tu red de referidos</li>
              <li>Obtener beneficios y comisiones</li>
              <li>Seguir tu progreso en tiempo real</li>
            </ul>
            <p style="font-size: 16px; line-height: 1.6;">Si tienes alguna pregunta o necesitas ayuda, no dudes en contactarnos.</p>
            <div style="margin-top: 40px; text-align: center;">
              <a href="${envs.FRONTEND_URL}/login" style="background-color: #0a8043; color: white; text-decoration: none; padding: 12px 25px; border-radius: 4px; font-weight: bold;">Ingresar a mi cuenta</a>
            </div>
            <p style="margin-top: 40px; font-size: 16px; line-height: 1.6;">¡Te deseamos mucho éxito!</p>
            <p style="font-size: 16px; line-height: 1.6;">
              Saludos,<br>
              El equipo de Nexus Platform
            </p>
          </div>
          <div style="text-align: center; padding-top: 20px; font-size: 12px; color: #888;">
            <p>Este es un mensaje automático, por favor no respondas a este correo.</p>
          </div>
        </div>
      `,
    });
  }
}
