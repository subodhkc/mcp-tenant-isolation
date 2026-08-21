/**
 * Path Boundary — project-root security boundary enforcement.
 *
 * The MCP server establishes ONE explicit allowed project root at startup.
 * All filesystem operations (scan target, config load, suppression read/write,
 * baseline read, custom rulepack load, output paths) must be constrained to
 * that root.
 *
 * Containment strategy:
 * - absolute resolution
 * - realpath where target exists (symlink-aware containment)
 * - normalized separators
 * - Windows case-insensitive path comparison
 * - UNC/outside-root path rejection
 *
 * This module NEVER silently normalizes an outside-root path back inside.
 * On any escape it throws PathBoundaryError with code TARGET_OUTSIDE_ALLOWED_ROOT
 * (or SYMLINK_ESCAPE / INVALID_PATH).
 *
 * Architectural pattern adapted (READ-ONLY reference) from the ai-appsec
 * producer's src/security/path-boundary.ts. No detector/rule semantics reused.
 * No runtime dependency on ai-appsec.
 *
 * PRODUCER_LOCAL_V2_CONFORMANCE.
 */

import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { existsSync } from 'node:fs';

export type PathBoundaryErrorCode =
  | 'TARGET_OUTSIDE_ALLOWED_ROOT'
  | 'SYMLINK_ESCAPE'
  | 'INVALID_PATH';

export class PathBoundaryError extends Error {
  readonly code: PathBoundaryErrorCode;
  readonly target?: string;
  readonly real?: string;
  constructor(
    code: PathBoundaryErrorCode,
    message: string,
    details?: { target?: string; real?: string }
  ) {
    super(message);
    this.code = code;
    this.name = 'PathBoundaryError';
    if (details) {
      this.target = details.target;
      this.real = details.real;
    }
  }
}

export interface ResolveOptions {
  /**
   * Whether to resolve symlinks via realpath when the target exists.
   * Default: true. Set false only for paths that may not exist yet
   * (e.g. an output file about to be written) — lexical containment
   * is still enforced.
   */
  readonly resolveSymlinks?: boolean;
  /**
   * If true and the target does not exist, allow the resolved lexical path
   * (still must be within root). Default: true (so output paths for files
   * not yet created are allowed). Set false to require existence.
   */
  readonly allowMissing?: boolean;
}

export class PathBoundary {
  private readonly root: string;
  private readonly rootNormalized: string;

  private constructor(root: string) {
    this.root = root;
    this.rootNormalized = normalizeForCompare(root);
  }

  /**
   * Create a PathBoundary rooted at the given directory.
   * The root is resolved to an absolute, real path and verified to be a directory.
   */
  static async create(root: string): Promise<PathBoundary> {
    if (!root || typeof root !== 'string') {
      throw new PathBoundaryError('INVALID_PATH', 'Root path must be a non-empty string');
    }
    if (isUNCPath(root)) {
      throw new PathBoundaryError(
        'TARGET_OUTSIDE_ALLOWED_ROOT',
        `UNC/network paths are not allowed as project root: ${root}`,
        { target: root }
      );
    }
    const resolved = path.resolve(root);
    if (!existsSync(resolved)) {
      throw new PathBoundaryError('INVALID_PATH', `Root does not exist: ${resolved}`, {
        target: resolved,
      });
    }
    const real = await fs.realpath(resolved);
    const stat = await fs.stat(real);
    if (!stat.isDirectory()) {
      throw new PathBoundaryError('INVALID_PATH', `Root is not a directory: ${real}`, {
        target: real,
      });
    }
    return new PathBoundary(real);
  }

  /**
   * Create a PathBoundary without async realpath (used for already-canonical roots).
   * Prefer create() wherever possible.
   */
  static createSync(root: string): PathBoundary {
    if (!root || typeof root !== 'string') {
      throw new PathBoundaryError('INVALID_PATH', 'Root path must be a non-empty string');
    }
    if (isUNCPath(root)) {
      throw new PathBoundaryError(
        'TARGET_OUTSIDE_ALLOWED_ROOT',
        `UNC/network paths are not allowed as project root: ${root}`,
        { target: root }
      );
    }
    const resolved = path.resolve(root);
    if (!existsSync(resolved)) {
      throw new PathBoundaryError('INVALID_PATH', `Root does not exist: ${resolved}`, {
        target: resolved,
      });
    }
    return new PathBoundary(resolved);
  }

  /**
   * Resolve a target path relative to the root, enforcing boundary constraints.
   * Throws PathBoundaryError if the path escapes the root.
   *
   * - Absolute targets are checked against root (must be within root).
   * - Relative targets are joined to root.
   * - `..` traversal that escapes root is rejected.
   * - Symlinks that resolve outside root are rejected.
   * - UNC paths are rejected.
   */
  async resolve(target: string, options: ResolveOptions = {}): Promise<string> {
    const { resolveSymlinks = true, allowMissing = true } = options;

    if (!target || typeof target !== 'string') {
      throw new PathBoundaryError('INVALID_PATH', 'Target path must be a non-empty string');
    }

    // Reject UNC/network paths (they reference external resources)
    if (isUNCPath(target)) {
      throw new PathBoundaryError(
        'TARGET_OUTSIDE_ALLOWED_ROOT',
        `UNC/network paths are not allowed: ${target}`,
        { target }
      );
    }

    // Resolve: absolute targets are taken as-is (then checked), relative joined to root
    const joined = path.isAbsolute(target) ? target : path.join(this.root, target);
    const resolved = path.resolve(joined);
    const lexicallyInside = isWithinRoot(resolved, this.rootNormalized);

    // If the target exists, resolve its real path. This handles:
    // - Windows 8.3 short-name paths (e.g. SUBODH~1 -> Subodh Kc)
    // - Symlinks that escape root
    // - Symlinks that stay within root
    if (resolveSymlinks && existsSync(resolved)) {
      let real: string;
      try {
        real = await fs.realpath(resolved);
      } catch {
        throw new PathBoundaryError(
          'INVALID_PATH',
          `Failed to resolve real path: ${resolved}`,
          { target, real: resolved }
        );
      }
      const reallyInside = isWithinRoot(real, this.rootNormalized);

      if (lexicallyInside && !reallyInside) {
        // Lexical said inside, but realpath says outside → symlink escape.
        throw new PathBoundaryError(
          'SYMLINK_ESCAPE',
          `Symlink escapes allowed project root: ${target} -> ${real}`,
          { target, real }
        );
      }
      if (!lexicallyInside && !reallyInside) {
        // Both lexical and realpath say outside → plain outside-root path.
        throw new PathBoundaryError(
          'TARGET_OUTSIDE_ALLOWED_ROOT',
          `Path escapes allowed project root: ${target} -> ${real}`,
          { target, real }
        );
      }
      // reallyInside is true → accept the canonical real path.
      return real;
    }

    // Target does not exist (or symlink resolution disabled): lexical containment only.
    if (!lexicallyInside) {
      throw new PathBoundaryError(
        'TARGET_OUTSIDE_ALLOWED_ROOT',
        `Path escapes allowed project root: ${target} -> ${resolved}`,
        { target, real: resolved }
      );
    }

    if (!allowMissing && !existsSync(resolved)) {
      throw new PathBoundaryError('INVALID_PATH', `Path does not exist: ${resolved}`, {
        target,
        real: resolved,
      });
    }

    return resolved;
  }

  /**
   * Synchronous lexical containment check (no symlink resolution).
   * Use only when async realpath is not available; prefer resolve() for full safety.
   */
  contains(target: string): boolean {
    if (!target || typeof target !== 'string') return false;
    if (isUNCPath(target)) return false;
    const joined = path.isAbsolute(target) ? target : path.join(this.root, target);
    const resolved = path.resolve(joined);
    return isWithinRoot(resolved, this.rootNormalized);
  }

  /** The canonical root path (realpath-resolved if created via create()). */
  getRoot(): string {
    return this.root;
  }
}

/**
 * Normalize a path for case-insensitive comparison.
 * On Windows: uppercase drive letter, lowercase the whole string for compare.
 * On POSIX: lowercase (case-sensitive filesystems still compare normalized
 * because we only use this for root-containment prefix checks where the root
 * itself is already canonical).
 */
function normalizeForCompare(p: string): string {
  const resolved = path.resolve(p);
  if (process.platform === 'win32') {
    // Uppercase drive letter, then lowercase entire string for case-insensitive compare
    const upper = resolved.charAt(0).toUpperCase() + resolved.slice(1);
    return upper.toLowerCase();
  }
  return resolved;
}

/**
 * Check if a target path is within the root using normalized comparison.
 * A path equal to the root is considered within root.
 */
function isWithinRoot(target: string, rootNormalized: string): boolean {
  const targetNorm = normalizeForCompare(target);
  if (targetNorm === rootNormalized) return true;
  // Ensure target is a proper subdirectory of root (prefix + separator)
  const rootWithSep = rootNormalized.endsWith(path.sep)
    ? rootNormalized
    : rootNormalized + path.sep;
  return targetNorm.startsWith(rootWithSep);
}

/**
 * Detect UNC/network paths (Windows \\server\share or //server/share).
 * These reference external resources and are rejected.
 */
function isUNCPath(p: string): boolean {
  return /^[\\/]{2}[^\\/]+[\\/]/.test(p);
}
