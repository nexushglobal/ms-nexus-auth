import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  NODE_ENV: 'development' | 'production' | 'test';
  NATS_SERVERS: string;
  JWT_SECRET: string;
  JWT_REFRESH_SECRET: string;
  FRONTEND_URL: string;
}

const envsSchema = joi
  .object({
    NATS_SERVERS: joi
      .string()
      .default('nats://localhost:4222')
      .description('NATS server URI'),
    PORT: joi.number().default(3000),
    NODE_ENV: joi
      .string()
      .valid('development', 'production', 'test')
      .default('development'),
    JWT_SECRET: joi
      .string()
      .required()
      .description('JWT secret for signing tokens'),
    JWT_REFRESH_SECRET: joi
      .string()
      .required()
      .description('JWT secret for signing refresh tokens'),
    FRONTEND_URL: joi
      .string()
      .default('http://localhost:3000')
      .description('URL of the frontend application'),
  })
  .unknown(true);

const { error, value } = envsSchema.validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

export const envs: EnvVars = value;
