import { config } from 'aws-sdk';

export const LocalstackConfig = {
  region: 'us-east-1',
  accessKeyId: 'test',
  secretAccessKey: 'test',
  endpoint: 'http://localhost:4566',
  sslEnabled: false,
};

config.update(LocalstackConfig);