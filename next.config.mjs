/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Served under lab.marwandiallo.com/identity so future labs (csp, ssrf, oauth)
  // can live alongside this one under a single branded host.
  basePath: "/identity",
  async redirects() {
    // Bare lab.marwandiallo.com/ → /identity until other labs land here.
    return [
      {
        source: "/",
        destination: "/identity",
        basePath: false,
        permanent: false,
      },
    ];
  },
};
export default nextConfig;
