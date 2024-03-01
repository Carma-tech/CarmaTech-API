import { config } from 'dotenv';
import { CognitoIdentityProviderClient, ListUsersCommand } from '@aws-sdk/client-cognito-identity-provider';
import { ConfigService } from '@nestjs/config';

const cognitoClient = new CognitoIdentityProviderClient({});

const configService = new ConfigService();
// fetchListUsers
export const checkUserExists = async (email: string) => {
  const command = new ListUsersCommand({
    UserPoolId: configService.get('USER_POOL_ID'),
    Filter: `email = "${email}"`,
    Limit: 1,
  });
  const { Users: users } = await cognitoClient.send(command);
  return users;
};
