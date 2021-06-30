import sucrase from '@rollup/plugin-sucrase'
import { nodeResolve } from '@rollup/plugin-node-resolve'

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
    plugins: [
        sucrase({ transforms: ['typescript'] }),
        nodeResolve(),
    ],
}
export default backend
