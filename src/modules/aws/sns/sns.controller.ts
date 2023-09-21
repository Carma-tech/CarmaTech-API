import { HttpService } from '@nestjs/axios';
import { Body, Controller, Get, Post } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as AWS from 'aws-sdk';
import { Logger } from '@aws-lambda-powertools/logger';

@Controller('sns-endpoint')
export class SnsController {
    private readonly logger = new Logger();
    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService
    ) {}

    @Post()
    processSNSNotification(@Body() snsMessage: any): string {
        // validate the message type
        if (snsMessage.Type === 'SubscriptionConfirmation') {
            // Handle SNS subscription URL callback
            // This URL should be fetched and visited to confirm the subscription.
            const confirmationUrl = snsMessage.SubscribeURL;
            this.logger.info(`Confirmation URL: ${confirmationUrl}`);
            // Make an HTTP GET request to the provided URL to confirm the subscription.
            try {
                const response = this.httpService.get(confirmationUrl);
                this.logger.info(`Confirmed subscription with response: ${JSON.stringify(response)}`);
               return 'Subscription successful';

            } catch (error) {
                this.logger.error("Error confirming subscription: ", error.message);
                return "Error confirming subscription2";
            }
        } else if (snsMessage.Type === 'Notification') {
            if (snsMessage.Status === 'COMPLETED') {
                // Handle completed Lambda task
                // Store the result, notify a user, etc.
                console.log('Lambda task completed successfully.');
            }

        }

        return 'OK';
    }
}
