const path = require('path');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const BundleTracker = require('webpack-bundle-tracker');
const { VueLoaderPlugin } = require('vue-loader');
const webpack = require('webpack');

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
      mail_compose: './src/js/mail_compose.js',
      mail_reader: './src/js/mail_reader.js',
    },

    output: {
      path: path.resolve(__dirname, '../file/static/file/bundles'),
      filename: isProd ? '[name]-[contenthash:8].js' : '[name].js',
      clean: true,
    },

    resolve: {
      alias: {
        vue$: 'vue/dist/vue.esm-bundler.js',
      },
      extensions: ['.js', '.vue'],
    },

    module: {
      rules: [
        {
          test: /\.vue$/,
          loader: 'vue-loader',
        },
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
      new webpack.DefinePlugin({
        __VUE_OPTIONS_API__: true,
        __VUE_PROD_DEVTOOLS__: false,
        __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: false,
      }),
      new VueLoaderPlugin(),
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
