import type { JestConfigWithTsJest } from 'ts-jest';
import dotenv from 'dotenv';

dotenv.config();

const config: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/src/**/*.test.ts'],
  rootDir: '../',
  moduleNameMapper: {
    '^bakosafe/(.*)$': '<rootDir>/sdk/$1',
  },
  transform: {
    '^.+\\.ts?$': [
      'ts-jest',
      {
        diagnostics: false,
      },
    ],
  },
};

export default config;
