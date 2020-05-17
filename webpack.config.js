const path = require('path')

config = {
  entry: {
    storage: path.resolve(__dirname, 'src', 'storage.js'),
    crypto: path.resolve(__dirname, 'src', 'crypto.js'),
    vault: path.resolve(__dirname, 'src', 'vault.js'),
  },
  output: {
    path: path.resolve(__dirname, 'build'),
  },
  module: {
    rules: [
      {
        test: /\.(js)$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
            plugins: ['@babel/plugin-transform-runtime'],
          },
        },
      },
    ],
  },
  devtool: 'source-map',
}

module.exports = [config]
