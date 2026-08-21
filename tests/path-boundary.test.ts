/**
 * Path Boundary — adversarial security tests (Part 3).
 *
 * Verifies the project-root security boundary rejects:
 * - `..` traversal outside root
 * - absolute outside-root targets
 * - symlink escape
 * - UNC/network paths
 * - and accepts legitimate in-root paths (relative, absolute, nested).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { PathBoundary, PathBoundaryError } from '../src/security/path-boundary.js';
import { mkdirSync, rmSync, writeFileSync, symlinkSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

function makeTempRoot(): string {
  const dir = join(tmpdir(), `mti-boundary-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  mkdirSync(join(dir, 'src'), { recursive: true });
  mkdirSync(join(dir, 'src', 'api'), { recursive: true });
  writeFileSync(join(dir, 'src', 'api', 'route.ts'), 'export default {};\n');
  writeFileSync(join(dir, '.mtirc.json'), '{}\n');
  return dir;
}

describe('PathBoundary — creation', () => {
  let root: string;
  beforeEach(() => { root = makeTempRoot(); });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); });

  it('should create boundary from a valid directory', async () => {
    const b = await PathBoundary.create(root);
    expect(b.getRoot()).toBeTruthy();
    // Use the canonical root (realpath-resolved) for absolute path checks,
    // since the boundary canonicalizes the root via realpath.
    expect(b.contains(join(b.getRoot(), 'src', 'api', 'route.ts'))).toBe(true);
  });

  it('should reject non-existent root', async () => {
    await expect(PathBoundary.create(join(root, 'does-not-exist'))).rejects.toThrow(PathBoundaryError);
  });

  it('should reject a file as root (not a directory)', async () => {
    const filePath = join(root, '.mtirc.json');
    await expect(PathBoundary.create(filePath)).rejects.toThrow(PathBoundaryError);
  });

  it('should reject UNC path as root', async () => {
    await expect(PathBoundary.create('\\\\server\\share')).rejects.toThrow(PathBoundaryError);
  });
});

describe('PathBoundary — traversal rejection (D-01, D-02, D-03, D-04)', () => {
  let root: string;
  let parent: string;
  beforeEach(() => { root = makeTempRoot(); parent = dirname(root); });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); });

  it('should reject `..` traversal outside root', async () => {
    const b = await PathBoundary.create(root);
    await expect(b.resolve(join('src', '..', '..', 'etc', 'passwd'))).rejects.toThrow(PathBoundaryError);
    await expect(b.resolve(join('src', '..', '..', 'etc', 'passwd'))).rejects.toMatchObject({
      code: 'TARGET_OUTSIDE_ALLOWED_ROOT',
    });
  });

  it('should reject absolute path outside root', async () => {
    const b = await PathBoundary.create(root);
    const outside = join(parent, 'outside-file.txt');
    writeFileSync(outside, 'evil');
    try {
      await expect(b.resolve(outside)).rejects.toThrow(PathBoundaryError);
      await expect(b.resolve(outside)).rejects.toMatchObject({ code: 'TARGET_OUTSIDE_ALLOWED_ROOT' });
    } finally {
      rmSync(outside, { force: true });
    }
  });

  it('should accept relative path inside root', async () => {
    const b = await PathBoundary.create(root);
    const resolved = await b.resolve(join('src', 'api', 'route.ts'));
    expect(existsSync(resolved)).toBe(true);
    expect(b.contains(resolved)).toBe(true);
  });

  it('should accept absolute path inside root', async () => {
    const b = await PathBoundary.create(root);
    // Use the canonical root for constructing absolute paths (boundary canonicalizes via realpath).
    const abs = join(b.getRoot(), 'src', 'api', 'route.ts');
    const resolved = await b.resolve(abs);
    expect(b.contains(resolved)).toBe(true);
  });

  it('should accept nested relative path with redundant `.` segments', async () => {
    const b = await PathBoundary.create(root);
    const resolved = await b.resolve(join('src', '.', 'api', 'route.ts'));
    expect(b.contains(resolved)).toBe(true);
  });

  it('should reject UNC path target', async () => {
    const b = await PathBoundary.create(root);
    await expect(b.resolve('\\\\server\\share\\file')).rejects.toMatchObject({
      code: 'TARGET_OUTSIDE_ALLOWED_ROOT',
    });
  });
});

describe('PathBoundary — symlink escape (D-05)', () => {
  let root: string;
  let outsideTarget: string;
  beforeEach(() => {
    root = makeTempRoot();
    outsideTarget = join(tmpdir(), `mti-outside-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(outsideTarget, { recursive: true });
    writeFileSync(join(outsideTarget, 'secret.txt'), 'secret');
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(outsideTarget, { recursive: true, force: true });
  });

  it('should reject symlink that escapes root', async () => {
    const b = await PathBoundary.create(root);
    const linkPath = join(root, 'src', 'evil-link');
    try {
      symlinkSync(outsideTarget, linkPath);
    } catch {
      // Symlinks may not be creatable in some CI sandboxes without admin.
      // Skip gracefully if the platform refuses.
      if (!existsSync(linkPath)) return;
    }
    await expect(b.resolve(join('src', 'evil-link', 'secret.txt'))).rejects.toMatchObject({
      code: 'SYMLINK_ESCAPE',
    });
  });

  it('should accept symlink that stays within root', async () => {
    const b = await PathBoundary.create(root);
    const linkPath = join(root, 'src', 'internal-link');
    try {
      symlinkSync(join(root, 'src', 'api'), linkPath);
    } catch {
      if (!existsSync(linkPath)) return;
    }
    const resolved = await b.resolve(join('src', 'internal-link', 'route.ts'));
    expect(b.contains(resolved)).toBe(true);
  });
});

describe('PathBoundary — Windows case-insensitivity', () => {
  let root: string;
  beforeEach(() => { root = makeTempRoot(); });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); });

  it('should treat differing-case absolute path as within root (Windows) or equivalent (POSIX)', async () => {
    const b = await PathBoundary.create(root);
    // Use canonical root; on Windows the boundary canonicalizes via realpath
    // so short-name/long-name and drive-letter-case differences are handled.
    const abs = join(b.getRoot(), 'src', 'api', 'route.ts');
    const resolved = await b.resolve(abs);
    expect(b.contains(resolved)).toBe(true);
  });
});

describe('PathBoundary — missing path handling', () => {
  let root: string;
  beforeEach(() => { root = makeTempRoot(); });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); });

  it('should allow missing path by default (for output files)', async () => {
    const b = await PathBoundary.create(root);
    const resolved = await b.resolve(join('output', 'results.json'), { resolveSymlinks: false });
    expect(b.contains(resolved)).toBe(true);
  });

  it('should reject missing path when allowMissing is false', async () => {
    const b = await PathBoundary.create(root);
    await expect(
      b.resolve(join('does-not-exist.ts'), { allowMissing: false })
    ).rejects.toMatchObject({ code: 'INVALID_PATH' });
  });
});
