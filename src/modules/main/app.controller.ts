import { Get, Controller, HttpStatus, Res, Render, Post, Body, HttpException, Delete, Param } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AppService } from '@modules/main/app.service';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';
import { join } from 'path';
import { SSMClient, PutParameterCommand, ParameterType, DeleteParameterCommand } from "@aws-sdk/client-ssm";

@Controller()
@ApiTags('healthcheck')
export class AppController {
  private ssmClient: SSMClient;
  constructor(
    private readonly appService: AppService,
    private readonly configService: ConfigService
  ) {
    this.ssmClient = new SSMClient({
      region: this.configService.get<string>('REGION')
    });
  }

  @Get()
  root() {
    return HttpStatus.OK;
  }

  @Get('config')
  @Render('config') // this is the config.ejs template. Omit .ejs when rendering
  getConfig() {
    return { jwt_expiration_time: this.configService.get('JWT_EXPIRATION_TIME') };
  }

  @Get('ddb_testing')
  ddb_test() {
    this.appService.ddb_test();
    return HttpStatus.OK;
  }

  @Get('eng-chinese-translator')
  @Render('eng-chinese-translator')  // renders the eng-chinese-translator.ejs file
  getTranslator() {
    return {
      lambdaFunctionName: this.configService.get('TRANSLATOR_LAMBDA_NAME'),
      identityPoolId: this.configService.get('IDENTITY_POOL_ID')
    };
  }

}
