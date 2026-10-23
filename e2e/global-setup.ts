import { execSync } from 'node:child_process';
import path from 'node:path';

// Bangun binary bughound sekali sebelum test. Dipisah dari webServer agar
// `go build` (yang mungkin perlu cache modul) tidak berjalan dengan env proxy
// mati yang dipakai untuk memblok egress saat server berjalan.
//
// Pakai execSync (lewat shell) agar `go` ter-resolve ke `go.exe` via PATHEXT di
// Windows; execFile tanpa shell tidak melakukannya.
export default async function globalSetup() {
  const root = path.resolve(__dirname, '..');
  const isWin = process.platform === 'win32';
  const out = isWin ? 'bughound-e2e.exe' : 'bughound-e2e';
  execSync(`go build -trimpath -o ${out} ./cmd/bughound`, {
    cwd: root,
    stdio: 'inherit',
  });
}
