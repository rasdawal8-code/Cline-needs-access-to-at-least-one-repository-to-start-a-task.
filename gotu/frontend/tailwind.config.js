/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        gotu: {
          bg:       '#0a0a0f',
          surface:  '#12121a',
          border:   '#1e1e2e',
          accent:   '#00d4aa',
          accent2:  '#0084ff',
          text:     '#e2e8f0',
          muted:    '#64748b',
          danger:   '#ef4444',
          warning:  '#f59e0b',
          success:  '#10b981',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
