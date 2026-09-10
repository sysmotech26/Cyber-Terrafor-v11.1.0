/** @type {import('tailwindcss').Config} */
export default { content: ['./index.html','./src/**/*.{js,jsx}'], theme: { extend: { boxShadow: { glow:'0 0 70px rgba(91,102,255,.16)' }, animation:{'pulse-slow':'pulse 3s ease-in-out infinite'} } }, plugins: [] }
