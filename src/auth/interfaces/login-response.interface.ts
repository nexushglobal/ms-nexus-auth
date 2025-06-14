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
    views: ViewResponse[];
  };
  accessToken: string;
  refreshToken: string;
}

export interface ViewResponse {
  id: string;
  code: string;
  name: string;
  icon?: string | null;
  url?: string | null;
  order: number;
  metadata?: {
    style?: {
      color?: string;
      backgroundColor?: string;
      fontSize?: string;
      fontWeight?: string;
      [key: string]: any;
    };
    [key: string]: any;
  } | null;
  children: ViewResponse[];
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
