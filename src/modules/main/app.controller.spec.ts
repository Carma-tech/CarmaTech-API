import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '../config/config.module';

describe('AppController', () => {
  let app: TestingModule;

  beforeAll(async () => {
    app = await Test.createTestingModule({
      controllers: [AppController],
      providers: [AppService],
      imports: [ConfigModule],
    }).compile();
  });

  describe('root', () => {
    it('should return "200"', () => {
      const appController = app.get<AppController>(AppController);
      expect(appController.root()).toBe(HttpStatus.OK);
    });
  });
});
