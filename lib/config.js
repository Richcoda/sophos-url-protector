// Central configuration for consistent secret key
export const config = {
    // Use environment variable or fallback for development
    SECRET_KEY: process.env.SECRET_KEY || 'dev-test-key-12345-change-in-production',
    domain: 'sophos-protector.com'
  };