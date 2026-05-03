/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        guardian: {
          red:    '#ff3b30',
          orange: '#ff9500',
          yellow: '#ffcc00',
          green:  '#34c759',
          blue:   '#007aff',
          dark:   '#1c1c1e',
          glass:  'rgba(28,28,30,0.85)',
        },
      },
      backdropBlur: { xs: '2px' },
    },
  },
  plugins: [],
};
