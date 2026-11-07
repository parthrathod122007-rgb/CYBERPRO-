import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  root: 'public',
  publicDir: false,
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'public/index.html'),
        about: resolve(__dirname, 'public/about.html'),
        ccce: resolve(__dirname, 'public/ccce.html'),
        programs: resolve(__dirname, 'public/programs.html'),
        contact: resolve(__dirname, 'public/contact.html'),
      }
    }
  }
});
