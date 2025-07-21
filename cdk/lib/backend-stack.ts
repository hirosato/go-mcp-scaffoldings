import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import { BasePathMapping, DomainName } from 'aws-cdk-lib/aws-apigateway';
import { Certificate } from 'aws-cdk-lib/aws-certificatemanager';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as efs from 'aws-cdk-lib/aws-efs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import * as path from 'path';

export interface MyAppBackendStackProps extends cdk.StackProps {
  environment: string;
  envSettings: any;
  regionSettings: any;
}

/**
 * Single stack containing all myapp.io resources
 */
export class MyAppBackendStack extends cdk.Stack {
  // Public properties for external access
  public readonly apiGateway: apigateway.RestApi;
  public readonly mcpGateway: apigateway.RestApi;
  public readonly userPool: cognito.UserPool;

  constructor(scope: Construct, id: string, props: MyAppBackendStackProps) {
    super(scope, id, props);

    const { environment, envSettings, regionSettings } = props;
    const isProduction = environment === 'prod';
    const appName = 'myapp';
    const regionShortName = regionSettings.shortName;

    // ========== AUTHENTICATION ==========

    // Cognito User Pool
    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `${appName}-${environment}-${regionShortName}`,
      selfSignUpEnabled: true,
      signInAliases: {
        email: true,
        phone: false,
        username: false
      },
      autoVerify: {
        email: true,
      },
      standardAttributes: {
        email: { required: true, mutable: true },
        nickname: { required: false, mutable: true },
        givenName: { required: false, mutable: true },
        familyName: { required: false, mutable: true },
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: isProduction ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY
    });

    const userPoolClient = this.userPool.addClient('ApiClient', {
      userPoolClientName: `${appName}-api-client-${environment}-${regionShortName}`,
      authFlows: {
        userPassword: true,
        userSrp: true,
        adminUserPassword: true
      },
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: false
        },
        scopes: [
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
          cognito.OAuthScope.COGNITO_ADMIN
        ],
        callbackUrls: [
          `https://${envSettings.domain}/auth/callback`,
          'http://localhost:3000/auth/callback'
        ],
        logoutUrls: [
          `https://${envSettings.domain}/auth/logout`,
          'http://localhost:3000/auth/logout'
        ]
      },
      preventUserExistenceErrors: true
    });

    // ========== OAUTH INFRASTRUCTURE ==========

    // OAuth DynamoDB table
    const oauthTable = new dynamodb.Table(this, 'OAuthTable', {
      tableName: `${appName}-oauth-${environment}-${regionShortName}`,
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'TTL',
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: isProduction
      },
      removalPolicy: isProduction ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
    });

    // OAuth GSIs
    // 1. GSI1 (Client Token Index): Essential for client management - allows revoking all tokens for a compromised client
    // 2. GSI2 (User Token Index): Critical for user security - enables logout functionality and revoking all user sessions
    // 3. GSI3 (Refresh Token Index): Required for OAuth token refresh flow - provides O(1) lookup when refreshing tokens
    ['GSI1', 'GSI2', 'GSI3'].forEach(indexName => {
      oauthTable.addGlobalSecondaryIndex({
        indexName,
        partitionKey: { name: `${indexName}PK`, type: dynamodb.AttributeType.STRING },
        sortKey: { name: `${indexName}SK`, type: dynamodb.AttributeType.STRING },
        projectionType: dynamodb.ProjectionType.ALL
      });
    });

    // OAuth KMS key for JWT signing
    const signingKey = new kms.Key(this, 'OAuthSigningKey', {
      description: 'OAuth JWT signing key',
      enableKeyRotation: isProduction,
      removalPolicy: isProduction ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    const signingKeyAlias = new kms.Alias(this, 'OAuthSigningKeyAlias', {
      aliasName: `alias/${appName}-oauth-signing-${environment}`,
      targetKey: signingKey,
    });

    // OAuth secrets
    const signingKeySecret = new secretsmanager.Secret(this, 'OAuthSigningKeySecret', {
      secretName: `${appName}/oauth/signing-key/${environment}`,
      description: 'OAuth JWT signing key material',
      removalPolicy: isProduction ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    const oauthAdminTokenSecret = new secretsmanager.Secret(this, 'OAuthAdminTokenSecret', {
      secretName: `${appName}/oauth/admin-token/${environment}`,
      description: 'OAuth admin token for client registration',
      generateSecretString: {
        passwordLength: 32,
        excludeCharacters: ' "\'\\',
      },
      removalPolicy: isProduction ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // ========== LAMBDA FUNCTIONS ==========

    // Lambda execution role
    const lambdaRole = new iam.Role(this, 'LambdaExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaVPCAccessExecutionRole')
      ]
    });

    // Grant permissions
    oauthTable.grantReadWriteData(lambdaRole);
    signingKey.grantDecrypt(lambdaRole);
    signingKeySecret.grantRead(lambdaRole);
    signingKeySecret.grantWrite(lambdaRole);
    oauthAdminTokenSecret.grantRead(lambdaRole);

    // Common Lambda properties
    const commonLambdaProps = {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      role: lambdaRole,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      environment: {
        USER_POOL_ID: this.userPool.userPoolId,
        USER_POOL_CLIENT_ID: userPoolClient.userPoolClientId,
        ENVIRONMENT: environment,
        REGION: regionShortName,
        OAUTH_TABLE_NAME: oauthTable.tableName,
        OAUTH_SIGNING_KEY_ALIAS: signingKeyAlias.aliasName,
        OAUTH_SIGNING_KEY_SECRET: signingKeySecret.secretName,
        OAUTH_ADMIN_TOKEN_SECRET: oauthAdminTokenSecret.secretName,
        BASE_URL: 'dev' == props.environment ? 'https://api.dev.myapp.io' : 'https://api.myapp.io',
        BASE_MCP_URL: 'dev' == props.environment ? 'https://mcp.dev.myapp.io' : 'https://mcp.myapp.io',
        BASE_WEB_URL: 'dev' == props.environment ? 'https://dev.myapp.io' : 'https://myapp.io',
      }
    };

    // MCP Lambda functions
    const mcpFunction = new lambda.Function(this, 'MCPServerFunction', {
      ...commonLambdaProps,
      functionName: `${appName}-mcp-${environment}-${regionShortName}`,
      logGroup: new logs.LogGroup(this, 'MCPServerFunctionLogGroup', { logGroupName: `lambda-log-${appName}-mcp-${environment}-${regionShortName}`, retention: isProduction ? logs.RetentionDays.SIX_MONTHS : logs.RetentionDays.TWO_YEARS }),
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../backend/bin/mcp')),
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      tracing: lambda.Tracing.ACTIVE,
    });
    const oauthFunction = new lambda.Function(this, 'OAuthServerFunction', {
      ...commonLambdaProps,
      functionName: `${appName}-oauth-${environment}-${regionShortName}`,
      logGroup: new logs.LogGroup(this, 'OAuthServerFunctionLogGroup', { logGroupName: `lambda-log-${appName}-oauth-${environment}-${regionShortName}`, retention: isProduction ? logs.RetentionDays.SIX_MONTHS : logs.RetentionDays.TWO_YEARS }),
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../backend/bin/oauth')),
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      tracing: lambda.Tracing.ACTIVE,
    });

    const authorizerFunction = new lambda.Function(this, 'OAuthAuthorizerFunction', {
      ...commonLambdaProps,
      functionName: `${appName}-oauth-authorizer-${environment}-${regionShortName}`,
      logGroup: new logs.LogGroup(this, 'OAuthAuthorizerFunctionLogGroup', { logGroupName: `lambda-log-${appName}-oauth-authorizer-${environment}-${regionShortName}`, retention: isProduction ? logs.RetentionDays.SIX_MONTHS : logs.RetentionDays.TWO_YEARS }),
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../backend/bin/authorizer')),
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      tracing: lambda.Tracing.ACTIVE,
    });

    // ========== API GATEWAY ==========

    this.apiGateway = new apigateway.RestApi(this, 'Api', {
      restApiName: `${appName}-api-${environment}-${regionShortName}`,
      description: `myapp.io API - ${environment} environment - ${regionShortName} region`,
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: [
          'Content-Type', 'X-Amz-Date', 'Authorization', 'X-Api-Key', 'X-Amz-Security-Token', 'X-Tenant-Id'
        ],
        allowCredentials: true
      },
      deployOptions: {
        stageName: environment,
        loggingLevel: isProduction ? apigateway.MethodLoggingLevel.ERROR : apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: isProduction ? false : true,
        metricsEnabled: true,
      }
    });
    this.mcpGateway = new apigateway.RestApi(this, 'McpApi', {
      restApiName: `${appName}-mcp-api-${environment}-${regionShortName}`,
      description: `myapp.io API - ${environment} environment - ${regionShortName} region`,
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: [
          'Content-Type', 'X-Amz-Date', 'Authorization', 'X-Api-Key', 'X-Amz-Security-Token', 'X-Tenant-Id'
        ],
        allowCredentials: true
      },
      deployOptions: {
        stageName: environment,
        cacheClusterEnabled: true,
        methodOptions: {
          "/.well-known/oauth-authorization-server/GET": {
            cachingEnabled: true,
            cacheTtl: cdk.Duration.minutes(5)
          },
          "/.well-known/oauth-protected-resource/GET": {
            cachingEnabled: true,
            cacheTtl: cdk.Duration.minutes(5)
          },
          "/.well-known/jwks.json/GET": {
            cachingEnabled: true,
            cacheTtl: cdk.Duration.minutes(5)
          },
        },
        loggingLevel: isProduction ? apigateway.MethodLoggingLevel.ERROR : apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: isProduction ? false : true,
        metricsEnabled: true,
      }
    });

    const cognitoMcpAuthorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'McpAuthorizer', {
      cognitoUserPools: [this.userPool],
      authorizerName: `${appName}-mcp-authorizer-${environment}-${regionShortName}`,
      identitySource: 'method.request.header.Authorization'
    });

    // OAuth Lambda authorizer
    const oauthAuthorizer = new apigateway.RequestAuthorizer(this, 'OAuthAuthorizer', {
      handler: authorizerFunction,
      identitySources: [apigateway.IdentitySource.header('Authorization')],
      resultsCacheTtl: cdk.Duration.minutes(10),
    });

    // ========== API ENDPOINTS ==========


    // OAuth endpoints
    const oauthIntegration = new apigateway.LambdaIntegration(oauthFunction);
    const mcpIntegration = new apigateway.LambdaIntegration(mcpFunction);
    // const mcpIntegration = new apigateway.LambdaIntegration(mcpServerLambda);

    const mcpGatewayRoot = this.mcpGateway.root

    const mainEndpoint = mcpGatewayRoot //.addResource('mcp')
    // The one returns 401 with WWW-Authenticate header
    mainEndpoint.addMethod('GET', new apigateway.MockIntegration({
      integrationResponses: [{
        statusCode: '405',
        responseParameters: {
          'method.response.header.Allow': "'POST'"
        },
        responseTemplates: {
          'application/json': '{"jsonrpc":"2.0","error":{"code":-32000,"message":"Method not allowed"},"id":null}'
        }
      }],
      requestTemplates: {
        'application/json': '{"statusCode": 405}'
      }
    }), {
      methodResponses: [{
        statusCode: '405',
        responseParameters: {
          'method.response.header.Allow': true
        }
      }]
    });
    mainEndpoint.addMethod('POST', mcpIntegration, {
      authorizer: oauthAuthorizer,
      authorizationType: apigateway.AuthorizationType.CUSTOM
    });


    // .well-known endpoints
    const wellKnownResource = mcpGatewayRoot.addResource('.well-known');
    wellKnownResource.addResource('oauth-authorization-server').addMethod('GET', oauthIntegration);
    wellKnownResource.addResource('oauth-protected-resource').addMethod('GET', oauthIntegration);
    wellKnownResource.addResource('jwks.json').addMethod('GET', oauthIntegration);

    // OAuth endpoints
    const oauthResource = mcpGatewayRoot.addResource('oauth');
    const authorizeResource = oauthResource.addResource('authorize');

    authorizeResource.addResource('callback').addMethod('POST', oauthIntegration, {
      authorizer: cognitoMcpAuthorizer,
      authorizationType: apigateway.AuthorizationType.COGNITO,
    });

    oauthResource.addResource('token').addMethod('POST', oauthIntegration);
    oauthResource.addResource('register').addMethod('POST', oauthIntegration);
    oauthResource.addResource('validate').addMethod('GET', oauthIntegration, {
      authorizer: oauthAuthorizer,
      authorizationType: apigateway.AuthorizationType.CUSTOM
    })

    // ========== MONITORING ==========

    if (isProduction) {
      // API Gateway alarms
      new cloudwatch.Alarm(this, '4xxErrorAlarm', {
        metric: this.apiGateway.metricClientError(),
        threshold: 10,
        evaluationPeriods: 3,
        datapointsToAlarm: 2,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        alarmDescription: 'API Gateway 4XX error rate is high',
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
      });

      new cloudwatch.Alarm(this, '5xxErrorAlarm', {
        metric: this.apiGateway.metricServerError(),
        threshold: 5,
        evaluationPeriods: 3,
        datapointsToAlarm: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        alarmDescription: 'API Gateway 5XX error rate is high',
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
      });

     
    }

    // ========== OUTPUTS ==========

    new cdk.CfnOutput(this, 'ApiGatewayUrl', {
      value: this.apiGateway.url,
      description: 'The URL of the API Gateway'
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: this.userPool.userPoolId,
      description: 'The ID of the Cognito User Pool'
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: userPoolClient.userPoolClientId,
      description: 'The ID of the Cognito User Pool Client'
    });


    new cdk.CfnOutput(this, 'OAuthTableName', {
      value: oauthTable.tableName,
      description: 'The name of the OAuth DynamoDB table'
    });

    new cdk.CfnOutput(this, 'OAuthSigningKeyId', {
      value: signingKey.keyId,
      description: 'The ID of the OAuth signing KMS key'
    });

    new cdk.CfnOutput(this, 'OAuthAdminTokenSecretName', {
      value: oauthAdminTokenSecret.secretName,
      description: 'The name of the OAuth admin token secret in Secrets Manager'
    });

  }
}