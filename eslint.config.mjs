import eslintConfig from '@iobroker/eslint-config';
export default [...eslintConfig, { files: ['src/**/*.ts'], rules: { '@typescript-eslint/no-explicit-any': 'off', 'jsdoc/require-jsdoc': 'off' } }];
