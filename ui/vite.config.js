import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    outDir: '../static',
    emptyOutDir: false,
    rollupOptions: {
      preserveEntrySignatures: 'exports-only',
      input: {
        editor: resolve(__dirname, 'src/editor.js'),
        graph: resolve(__dirname, 'src/graph.js'),
      },
      output: {
        entryFileNames: '[name]-bundle.js',
        chunkFileNames: '[name]-chunk.js',
        format: 'esm',
      },
    },
  },
});
