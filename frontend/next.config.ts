import type { NextConfig } from "next";

// Static export only: the result in out/ is served by the Python server (tripwire/server.py) on
// the same origin as the API, so the backend's header and Origin checks apply unchanged.
const config: NextConfig = {
  output: "export",
  reactStrictMode: true,
  images: { unoptimized: true },
};

export default config;
