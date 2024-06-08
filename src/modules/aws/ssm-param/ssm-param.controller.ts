import { DeleteParameterCommand, GetParametersByPathCommand, ParameterType, PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { Body, Controller, Delete, Get, HttpException, HttpStatus, Param, Post, Query } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Controller('ssm-params')
export class SsmParamController {
    private ssmClient: SSMClient;
    constructor(
        private readonly configService: ConfigService,
    ) {
        this.ssmClient = new SSMClient({ region: this.configService.get<string>('REGION') });
    }

    @Get()
    async getParams(@Query('path') path: string = '/') {
        try {
            const command = new GetParametersByPathCommand({
                Path: path,
                Recursive: true,
                WithDecryption: true,
            });
            const response = await this.ssmClient.send(command);
            console.log('Parameters response: ', response);
            const simplifiedParameters = response.Parameters.map(param => ({
                Name: param.Name,
                Value: param.Value
            }));
            return simplifiedParameters;
        } catch (error) {
            throw new HttpException(
                `Failed to list SSM parameters: ${error.message}`,
                HttpStatus.INTERNAL_SERVER_ERROR
            );
        }
    }

    @Post()
    async createOrUpdateParams(@Body() params: Record<string, any>) {
        try {
            if (Object.keys(params).length === 0) {
                throw new HttpException(
                    'No parameters provided. Please enter at least one parameter name and value.',
                    HttpStatus.BAD_REQUEST
                );
            }
            // Iterate over the object keys and values to create/update parameters
            const results = [];
            for (const [key, value] of Object.entries(params)) {
                if (!key.trim() || !value.trim()) {
                    throw new HttpException(
                        'Both name and value are required for each parameter. Please enter both.',
                        HttpStatus.BAD_REQUEST
                    );
                }
                const input = {
                    Name: key,
                    Value: value,
                    Type: 'String' as ParameterType,
                    Overwrite: true,
                };
                const command = new PutParameterCommand(input);
                const response = await this.ssmClient.send(command);
                console.log('Create/Updated Parameter:', response);
                results.push({ key, response });
            }
            return {
                statusCode: 200,
                message: 'Parameters created or updated successfully',
            };
        } catch (error) {
            throw new HttpException(
                `Failed to create or update SSM parameters: ${error.message}`,
                HttpStatus.INTERNAL_SERVER_ERROR
            );
        }
    }

    @Delete('/:name')
    async deleteParam(@Param('name') name: string) {
        if (!name.trim()) {
            throw new HttpException(
                'Parameter name is required and cannot be empty.',
                HttpStatus.BAD_REQUEST
            );
        }

        const input = { Name: name };
        const command = new DeleteParameterCommand(input);

        try {
            const response = await this.ssmClient.send(command);
            return { message: 'Parameter deleted successfully', response };
        } catch (error) {
            // Handle the case where the parameter does not exist
            if (error.name === 'ParameterNotFound') {
                throw new HttpException('Parameter not found.', HttpStatus.NOT_FOUND);
            }
            // Other AWS errors
            throw new HttpException(
                `Failed to delete SSM parameter: ${error.message}`,
                HttpStatus.INTERNAL_SERVER_ERROR
            );
        }
    }
}
