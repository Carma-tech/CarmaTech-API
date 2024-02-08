import { BadRequestException, ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { Hash } from '@app/utils/hash.util';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '@modules/user/user.service';
import { User } from '@modules/user/user.entity';
import { SigninDto } from '@modules/auth/dto/signin.dto';
import cognito, {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  ResendConfirmationCodeCommand,
  AuthFlowType,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { RegisterRequestDto } from './dto/register.dto';
import { checkUserExists } from '@app/utils/helper.util';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { Logger } from '@aws-lambda-powertools/logger';

@Injectable()
export class AuthService {
  private cognitoIdentity: CognitoIdentityProviderClient;
  private readonly snsClient: SNSClient;
  private readonly snsTopicArn: string;
  private subject: string;
  private readonly logger = new Logger();
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UsersService,
  ) {
    this.cognitoIdentity = new CognitoIdentityProviderClient({ region: 'us-east-2' });
    this.snsClient = new SNSClient({ region: 'us-east-2' });
    this.snsTopicArn = this.configService.get<string>('SNS_TOPIC_ARN');
  }

  // Send SNS notification handler
  async sendSnsNotification(subject: string, message: string): Promise<void> {
    try {
      const command = new PublishCommand({
        TopicArn: this.snsTopicArn,
        Subject: subject,
        Message: message,
      });
      await this.snsClient.send(command);
    } catch (error) {
      console.log(`Error Sending SNS Notification ${error}`)
      throw error;
    }
  }

  async registerIncognitoUser(registerDto: RegisterRequestDto) {
    // check if user exists in cognito
    const userExists = await checkUserExists(registerDto.email);
    if (userExists.length > 0) {
      // Send SNS Notification
      this.subject = 'User Registration Error';
      await this.sendSnsNotification(this.subject, 'User Already exists');
      throw new ConflictException('User already exists');
    }
    let attributes = [
      { Name: 'name', Value: registerDto.name },
      { Name: 'username', Value: registerDto.username },
      { Name: 'email', Value: registerDto.email },
    ];

    try {
      const input = {
        ClientId: this.configService.get<string>('USER_CLIENT_ID'),
        Username: registerDto.email,
        Password: registerDto.password,
        UserAttributes: attributes,
        ValidationData: attributes,
      };
      const signupCommand = new SignUpCommand(input);
      const response = await this.cognitoIdentity.send(signupCommand);
      const email = registerDto.email;
      return {
        statusCode: response.$metadata.httpStatusCode,
        message: `User created successfully, check your email ${email} to confirm your account`,
      };
    } catch (error) {
      const awsError = error as AWSError;
      let message: string;
      switch (awsError.name) {
        case 'UsernameExistsException':
          message = 'User already exists';
          break;
        case 'InvalidParameterException':
          message = 'Invalid parameters provided';
          break;
        case 'UserNotFoundException':
          break;
        case 'TooManyRequestsException':
          message = 'Too many requests, please try again later';
          break;
        default:
          message = `An unexpected error occurred ${awsError.message}`;
          break;
      }
      // Send SNS notification
      this.subject = 'User Registration Error';
      await this.sendSnsNotification(this.subject, message);
      return { message: message, details: awsError };

    }
  }

  async confirmIncognitoUser(email: string, confirmationCode: string) {
    try {
      const input = {
        ClientId: this.configService.get<string>('USER_CLIENT_ID'),
        Username: email,
        ConfirmationCode: confirmationCode
      };
      const confirmSignUpCommand = new ConfirmSignUpCommand(input);
      const response = await this.cognitoIdentity.send(confirmSignUpCommand);
      return {
        statusCode: response.$metadata.httpStatusCode,
        message: 'User confirmed successfully',
      };

    } catch (error) {
      const awsError = error as AWSError;
      let message: string;
      switch (awsError.name) {
        case 'UserNotFoundException':
          message = 'User not found';
          break;
        case 'CodeMismatchException':
          message = 'Code mismatch';
          break;
        case 'NotAuthorizedException':
          message = 'Not authorized';
          break;
        case 'ExpiredCodeException':
          message = 'Expired code';
          break;
        default:
          message = `An unexpected error occurred ${awsError.message}`;
          break;
      }
      // Send SNS notification
      this.subject = 'User Confirmation Error';
      await this.sendSnsNotification(this.subject, message);
      return { message: message, details: awsError };
    }
  }

  // resend confirmation code API if code expires or not received
  async resendConfirmationCode(email: string) {
    try {
      const input = {
        ClientId: this.configService.get<string>('COGNITO_USER_CLIENT_ID'),
        Username: email,
      };
      const resendCommand = new ResendConfirmationCodeCommand(input);
      const response = await this.cognitoIdentity.send(resendCommand);
      return {
        statusCode: response.$metadata.httpStatusCode,
        message: 'Confirmation code resent successfully, please check your email',
      };
    } catch (error) {
      const awsError = error as AWSError;
      this.subject = 'Resend Confirmation Code Error';
      await this.sendSnsNotification(this.subject, awsError.message);
      return {
        message: awsError.name,
        statusCode: awsError.$metadata.httpStatusCode
      }
    }
  }

  // Signin Incognito User API
  async signinIncognitoUser(authenticateRequest: SigninDto) {
    try {
      const params = {
        AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
        ClientId: this.configService.get<string>('COGNITO_USER_CLIENT_ID'),
        AuthParameters: {
          USERNAME: authenticateRequest.email,
          PASSWORD: authenticateRequest.password
        },
      };
      const command = new InitiateAuthCommand(params);
      const response = await this.cognitoIdentity.send(command);
      return {
        message: response,
        statusCode: response.$metadata.httpStatusCode
      };
    } catch (error) {
      const awsError = error as AWSError;
      this.subject = 'Signin Incognito User Error';
      await this.sendSnsNotification(this.subject, awsError.message);
      return {
        message: awsError.name,
        statusCode: awsError.$metadata.httpStatusCode
      }
    }
  }

  // forgot password API
  async forgotPassword(email: string) {
    try {
      const input = {
        ClientId: this.configService.get<string>('COGNITO_USER_CLIENT_ID'),
        Username: email,
      }
      this.logger.info(`ResendConfirmationCodeCommand input: ${JSON.stringify(input)}`);

      const forgotCommand = new ForgotPasswordCommand(input);
      this.logger.info(`forgotCommand: ${JSON.stringify(forgotCommand)}`);
      const response = await this.cognitoIdentity.send(forgotCommand);
      this.logger.info(`response: ${JSON.stringify(response)}`);
      return {
        statusCode: response.$metadata.httpStatusCode,
        message: 'Password reset link sent successfully',
      };

    } catch (error) {
      this.logger.error(`Error message: ${error.message}`);
      const awsError = error as AWSError;
      // Send SNS notification
      this.subject = 'Incognito User Forgot Password Error';
      await this.sendSnsNotification(this.subject, awsError.message);
      return {
        message: awsError.message,
        statusCode: awsError.$metadata.httpStatusCode
      };
    }
  }

  async confirmForgotPassword(email: string, confirmationCode: string, password: string) {
    try {
      const input = {
        ClientId: this.configService.get<string>('COGNITO_USER_CLIENT_ID'),
        Username: email,
        ConfirmationCode: confirmationCode,
        Password: password,
      }

      const confirmForgotPasswdCommand = new ConfirmForgotPasswordCommand(input);
      const response = await this.cognitoIdentity.send(confirmForgotPasswdCommand);
      return {
        statusCode: response.$metadata.httpStatusCode,
        message: 'Password reset successfully',
      };
    } catch (error) {
      const awsError = error as AWSError;
      // Send SNS notification
      this.subject = 'Confirming Password Error';
      await this.sendSnsNotification(this.subject, awsError.message);
      return {
        message: awsError.message,
        statusCode: awsError.$metadata.httpStatusCode
      }
    }
  }


  async createToken(user: User) {
    return {
      expiresIn: this.configService.get<string>('JWT_EXPIRATION_TIME'),
      accessToken: this.jwtService.sign({ id: user.id }),
      user,
    };
  }

  async validateUser(signinDto: SigninDto): Promise<any> {
    const user = await this.userService.getByEmail(signinDto.email);
    if (!user || !Hash.compare(signinDto.password, user.password)) {
      throw new UnauthorizedException('Invalid credentials!');
    }
    return user;
  }
}

interface AWSError extends Error {
  name: string; // Name of the exception
  $metadata: { httpStatusCode: number };
}
