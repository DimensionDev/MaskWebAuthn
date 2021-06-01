import rollup from 'rollup'
import sucrase from '@rollup/plugin-sucrase'

/** @type {rollup.RollupOptions} */
const api = {
    input: './api/index.ts',
    output: {
        file: './dist/api.js',
        format: 'esm',
    },
    plugins: [sucrase({ transforms: ['typescript'] })],
}
/** @type {rollup.RollupOptions} */
const backend = {
    input: './backend/index.ts',
    output: {
        file: './dist/backend.js',
        format: 'esm',
    },
    plugins: [sucrase({ transforms: ['typescript'] })],
}
export default [api, backend]
