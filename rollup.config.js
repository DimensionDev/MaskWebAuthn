import rollup from 'rollup'
import sucrase from '@rollup/plugin-sucrase'

/** @type {rollup.RollupOptions} */
const backend = {
    input: {
        backend: './backend/index.ts',
        api: './api/index.ts',
        playground: './playground/index.ts',
    },
    output: {
        dir: './dist/',
        format: 'esm',

    },
    plugins: [sucrase({ transforms: ['typescript'] })],
}
export default backend
