// Bundles the app and the analysis worker with esbuild.
//   node build.mjs           -> dist/ (production, network blocked by CSP)
//   node build.mjs --serve   -> dev server with live reload on http://localhost:5173
import * as esbuild from 'esbuild'
import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises'

const serve = process.argv.includes('--serve')

const options = {
  entryPoints: { app: 'src/main.jsx', worker: 'src/worker.js', 'disasm-worker': 'src/disasm/disasm-worker.js' },
  outdir: 'dist',
  bundle: true,
  minify: !serve,
  sourcemap: serve,
  jsx: 'automatic',
  target: ['es2022', 'chrome110', 'firefox110', 'safari16'],
  define: { 'process.env.NODE_ENV': JSON.stringify(serve ? 'development' : 'production') },
  loader: { '.css': 'css', '.wasm': 'binary' },
  logLevel: 'info',
}

async function writeHtml() {
  const html = (await readFile('public/index.html', 'utf8')).replaceAll('__CONNECT__', serve ? "'self'" : "'none'")
  await mkdir('dist', { recursive: true })
  await writeFile('dist/index.html', html)
  await copyFile('public/_headers', 'dist/_headers')
}

await writeHtml()

if (serve) {
  const ctx = await esbuild.context(options)
  await ctx.watch()
  const { host, port } = await ctx.serve({ servedir: 'dist', port: 5173 })
  console.log(`Teardown dev server: http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`)
} else {
  await esbuild.build(options)
}
