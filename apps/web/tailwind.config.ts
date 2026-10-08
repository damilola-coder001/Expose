import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "#090b0e",
        foreground: "#e2e8f0",
        canvas: "#090b0e",
        panel: "#0d1117",
        surface: {
          50: "#0e131a",
          100: "#131923",
          200: "#18202d",
          300: "#1f2838",
          400: "#273245",
        },
        border: {
          subtle: "#171d28",
          DEFAULT: "#202735",
          strong: "#2c3547",
        },
        accent: {
          DEFAULT: "#10b981",
          hover: "#059669",
          subtle: "rgba(16, 185, 129, 0.1)",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
