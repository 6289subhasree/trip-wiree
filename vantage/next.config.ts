import type { NextConfig } from "next";

const config: NextConfig = {
  output: "export",
  reactStrictMode: true,
  images: { unoptimized: true },
  // The export in out/ is committed; a fixed id keeps rebuild diffs small.
  generateBuildId: () => "tripwire-landing",
};

export default config;
