module.exports = {
  env: {
    browser: true,
    es2021: true,
    'shared-node-browser': true
  },
  extends: [
    'standard'
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module'
  },
  plugins: [
    '@typescript-eslint',
    'unused-imports'
  ],
  rules: {
    'constructor-super': 'error',
    'dot-notation': 'error',
    eqeqeq: 'error',
    'no-undef': 'off',
    'no-bitwise': 'error',
    'no-debugger': 'error',
    'no-eval': 'error',
    'no-extra-bind': 'error',
    'no-fallthrough': 'error',
    'no-new-wrappers': 'error',
    'no-plusplus': 'error',
    'no-restricted-globals': ['error', 'event', 'name', 'length', 'closed'],
    'no-unused-vars': 'warn',
    'no-return-await': 'error',
    'no-sparse-arrays': 'error',
    'no-template-curly-in-string': 'error',
    'prefer-const': 'warn',
    'use-isnan': 'error',
    'unused-imports/no-unused-imports-ts': 'error'
  }
}
