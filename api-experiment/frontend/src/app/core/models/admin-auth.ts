export interface IBodyLogin {
  email: string;
  password: string;
}

export interface IResponseLogin {
  access: string;
  refresh: string;
}
