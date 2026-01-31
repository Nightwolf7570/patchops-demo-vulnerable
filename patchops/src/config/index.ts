import { config } from 'dotenv';

config();

export const GITHUB_CONFIG = {
  token: process.env.GITHUB_TOKEN || '',
  apiVersion: '2022-11-28',
};

export const BOT_CONFIG = {
  name: process.env.BOT_NAME || 'PatchBot',
  email: process.env.BOT_EMAIL || 'patchbot@patchops.dev',
  username: process.env.BOT_USERNAME || 'patchbot',
};

export const OPENROUTER_CONFIG = {
  apiKey: process.env.OPENROUTER_API_KEY || '',
  baseUrl: 'https://openrouter.ai/api/v1',
  model: 'anthropic/claude-3-haiku',  // Valid OpenRouter model ID
  // Alternative: 'openai/gpt-3.5-turbo' or 'anthropic/claude-3-sonnet'
};

export const SERVER_CONFIG = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
};

export const DEMO_CONFIG = {
  owner: process.env.DEMO_REPO_OWNER || 'patchops-demo',
  repo: process.env.DEMO_REPO_NAME || 'patchops-demo-vulnerable',
};

export const LOG_CONFIG = {
  level: process.env.LOG_LEVEL || 'info',
};

// Validate required config
export function validateConfig(): void {
  if (!GITHUB_CONFIG.token) {
    throw new Error('GITHUB_TOKEN is required. Set it in .env file.');
  }
  
  if (!OPENROUTER_CONFIG.apiKey) {
    console.warn('⚠️  OPENROUTER_API_KEY not set. LLM features will be mocked.');
  }
}
