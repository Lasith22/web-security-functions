module.exports = {
  env: {
    es6: true,
    node: true,
  },
  parserOptions: {
    ecmaVersion: 2018,
  },
  extends: ['eslint:recommended', 'google'],
  rules: {
    'no-restricted-globals': 'off',
    'prefer-arrow-callback': 'off',
    quotes: 'off',
    indent: 'off',
    'comma-dangle': 'off',
    'object-curly-spacing': 'off',
    'max-len': 'off',
    'require-jsdoc': 'off',
  },
  overrides: [
    {
      files: ['**/*.spec.*'],
      env: {
        mocha: true,
      },
      rules: {},
    },
  ],
  globals: {},
};
