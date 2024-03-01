import { IsEmail, IsString, Matches } from 'class-validator';

export class RegisterRequestDto {
  @IsString()
  name: string;

  @IsString()
  username: string;

  @IsEmail()
  email: string;

  /* Minimum six characters, at least one uppercase letter, one lowercase letter, one number, and one special character */

  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$&+,:;=?@#|'<>.^*()%!-])[A-Za-z\d@$&+,:;=?@#|'<>.^*()%!-]{6,}$/,
    { message: 'invalid password' },
  )
  password: string;

}