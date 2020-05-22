const path = require('path')

config = {
  entry: {
    storage: path.resolve(__dirname, 'src', 'storage.js'),
    crypto: path.resolve(__dirname, 'src', 'crypto.js'),
    vault: path.resolve(__dirname, 'src', 'vault.js'),
    ['test.crypto']: path.resolve(__dirname, 'tests', 'test.crypto.js'),
  },
  output: {
    path: path.resolve(__dirname, 'build'),
  },
  // We're using different node.js modules in our code,
  // this prevents WebPack from failing on them or embedding
  // polyfills for them into the bundle.
  node: {
    __dirname: false,
    fs: 'empty',
    Buffer: false,
    process: false,
    crypto: 'empty',
  },
  module: {
    noParse: /\.wasm$/,
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
      {
        test: /\.wasm$/,
        // Tells WebPack that this module should be included as
        // base64-encoded binary file and not as code
        loaders: ['base64-loader'],
        // Disables WebPack's opinion where WebAssembly should be,
        // makes it think that it's not WebAssembly
        type: 'javascript/auto',
      },
    ],
  },

  devtool: 'source-map',
}

module.exports = [config]
