#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { MyAppBackendStack } from '../lib/backend-stack';
import { UsStack } from '../lib/stacks/us-stack';
import { EuStack } from '../lib/stacks/eu-stack';
import { JpStack } from '../lib/stacks/jp-stack';
import { MyAppFrontendStack } from '../lib/front-stack';

// Get environment from context or use default
const app = new cdk.App();
const env = app.node.tryGetContext('env') || 'dev';
const envSettings = app.node.tryGetContext('environments')[env];

// Regional context from CDK context
const regions = app.node.tryGetContext('regions');
const usRegion = regions.us;
const euRegion = regions.eu;
const jpRegion = regions.jp;

new UsStack(app, `MyAppApp-US-${env}`, {
  env: { 
    account: process.env.CDK_DEFAULT_ACCOUNT, 
    region: usRegion.name 
  },
  environment: env,
  envSettings: envSettings,
  regionSettings: usRegion,
  description: `myapp.io ${env} environment - US region stack`,
  crossRegionReferences: true
});

new MyAppFrontendStack(app, `MyAppFront-${env}`, {
  stage: env,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});