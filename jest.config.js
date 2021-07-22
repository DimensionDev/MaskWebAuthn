module.exports = {
    preset: 'ts-jest',
    setupFiles: ['./test/jest.setup.ts'],
    testEnvironment: 'node',
    modulePathIgnorePatterns: ['<rootDir>/dist/', '<rootDir>/out/'],
}
