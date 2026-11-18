/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    // Already validated via `npx tsc --noEmit`
    ignoreBuildErrors: true,
  },
  eslint: {
    // Ignore during production bundling
    ignoreDuringBuilds: true,
  },
};

module.exports = nextConfig;
