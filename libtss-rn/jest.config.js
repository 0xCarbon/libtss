module.exports = {
	preset: "ts-jest",
	testEnvironment: "node",
	testMatch: ["<rootDir>/src/__tests__/**/*.test.ts"],
	moduleNameMapper: {
		"^\\./NativeLibtss$": "<rootDir>/src/__tests__/__mocks__/NativeLibtss.ts",
	},
	transform: {
		"^.+\\.ts$": [
			"ts-jest",
			{
				tsconfig: {
					module: "commonjs",
				},
			},
		],
	},
};
