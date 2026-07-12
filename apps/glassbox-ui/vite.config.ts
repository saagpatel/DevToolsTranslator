import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: { environment: 'jsdom' },
  server: { port: 1421, strictPort: true },
  preview: { port: 1421, strictPort: true },
});
