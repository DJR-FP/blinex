/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  env: {
    NEXT_PUBLIC_MGMT_API: process.env.NEXT_PUBLIC_MGMT_API || 'http://localhost:8080',
  },
};

module.exports = nextConfig;
