import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite' // <-- The new plugin!

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(), // <-- Adding it here!
  ],
})