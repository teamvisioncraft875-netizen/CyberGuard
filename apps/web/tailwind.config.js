/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: "#0a0f1d",
          panel: "#131b2e",
          accent: "#00f0ff",
          danger: "#ff003c",
          warning: "#ffb703",
          success: "#00f5d4"
        }
      }
    },
  },
  plugins: [],
}
