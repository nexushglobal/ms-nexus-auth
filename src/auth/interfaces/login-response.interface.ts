export interface LoginResponse {
  user: {
    id: string;
    email: string;
    photo: string | null;
    nickname: string | null;
    firstName: string;
    lastName: string;
    role: {
      id: string;
      code: string;
      name: string;
    };
  };
  accessToken: string;
  refreshToken: string;
}

export interface JwtPayload {
  email: string;
  sub: string;
  role: {
    id: string;
    code: string;
    name: string;
  };
  iat?: number;
  exp?: number;
}

export interface CleanJwtPayload {
  email: string;
  sub: string;
  role: {
    id: string;
    code: string;
    name: string;
  };
}
