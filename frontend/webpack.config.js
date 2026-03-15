const path = require('path');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const BundleTracker = require('webpack-bundle-tracker');

module.exports = (env, argv) => {
  const isProd = argv.mode === 'production';

  return {
    entry: {
      common: './src/js/common.js',
      browse: './src/js/browse.js',
      users: './src/js/users.js',
      move_picker: './src/js/move_picker.js',
      editor: './src/js/editor_init.js',
      calendar: './src/js/calendar.js',
    },

    output: {
      path: path.resolve(__dirname, '../file/static/file/bundles'),
      filename: isProd ? '[name]-[contenthash:8].js' : '[name].js',
      clean: true,
    },

    module: {
      rules: [
        {
          test: /\.css$/,
          use: [
            MiniCssExtractPlugin.loader,
            'css-loader',
            'postcss-loader',
          ],
        },
      ],
    },

    plugins: [
      new MiniCssExtractPlugin({
        filename: isProd ? '[name]-[contenthash:8].css' : '[name].css',
      }),
      new BundleTracker({
        path: path.resolve(__dirname, '../file/static/file'),
        filename: 'webpack-stats.json',
      }),
    ],

    devtool: isProd ? 'source-map' : 'eval-source-map',
  };
};
