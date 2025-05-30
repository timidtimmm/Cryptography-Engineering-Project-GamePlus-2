// postcss.config.js
module.exports = {
  plugins: {
    // 直接用独立出来的 @tailwindcss/postcss
    '@tailwindcss/postcss': {},
    // 继续保留 Autoprefixer
    autoprefixer: {},
  },
};
