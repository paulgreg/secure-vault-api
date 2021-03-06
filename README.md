# secure-vault-api


That project is on stand-by (use of a self-hosted bitwarden).


That project is a part of a PWA based password manager.

That project is or will be composed of theses repositories :

- [secure-vault-pwa](https://github.com/paulgreg/secure-vault-pwa) : the Progressive Web Application,
- [secure-vault-api](https://github.com/paulgreg/secure-vault-api) : browser API about cryptgraphy & localStorage access,
- [secure-vault-server-node](https://github.com/paulgreg/secure-vault-server-node) : server code in node,
- secure-vault-web-extension : browser web extension.

That secure-vault-api contains :

- crypto.js : helper crypto functions using Web Crypto API,
- storage.js : functions about localStorage (mainly for handling not suported / accessible like when using private / incognito mode),
- vault.js : functions about vault

## Cryptography

That project uses Web Crypto API for random generation and aes encryption.

We use argon2id for key derivation and more specifically [antelle/argon2-browser](https://github.com/antelle/argon2-browser/)’s browser implementation (thanks).

## Tests

Since Web Crypto API requires a browser and requires TLS, you’ll need to generate a certificate by `npm run gen-cert` then launch web server via `npm run serve`.

Then launch `npm run dev` to build modules and open then the tests page from `tests` directory to launch Mocha tests suite.

You’ll need a modern decent browser since I’m using es6 features, async/await.

## Build

Webpack / babel is used to transform code.
