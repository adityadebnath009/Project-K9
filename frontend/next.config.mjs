/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  allowedDevOrigins: ['192.168.0.105', 'localhost', '127.0.0.1'],
  async redirects() {
    return [
      {
        source: '/overview',
        destination: '/',
        permanent: false,
      },
      {
        source: '/heuristics',
        destination: '/threats',
        permanent: false,
      },
      {
        source: '/knowledge',
        destination: '/crypto',
        permanent: false,
      },
      {
        source: '/knowledge-base',
        destination: '/crypto',
        permanent: false,
      },
      {
        source: '/guard',
        destination: '/quishing',
        permanent: false,
      },
    ];
  },
};

export default nextConfig;
