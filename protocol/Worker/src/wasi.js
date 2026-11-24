// WASI for the node's reactor inside a Durable Object: the calls Swift's
// runtime and swift-foundation's FileManager make, over a file tree kept in
// memory and in the Durable Object's SQLite storage.
//
// The tree is "/" preopened as fd 3. Every file and directory is a row of the
// `files` table (a directory's data is NULL), read when the object starts.
// A file opened for writing goes to its row when it's closed or synced, and
// a removal or rename the moment it happens, so by the time the reactor
// answers a request everything it wrote is in SQLite. A Durable Object's
// storage writes are committed before its response goes out (its output
// gate), which is the node's "persist before you sign" (spec §13).

const SUCCESS = 0, EBADF = 8, EEXIST = 20, EINVAL = 28, EISDIR = 31, ENOENT = 44, ENOSYS = 52,
  ENOTDIR = 54, ENOTEMPTY = 55, ENOTSUP = 58;
const DIRECTORY = 3, REGULAR_FILE = 4, CHARACTER_DEVICE = 2;
const O_CREAT = 1, O_DIRECTORY = 2, O_EXCL = 4, O_TRUNC = 8;
const FDFLAG_APPEND = 1;
const PREOPEN_FD = 3;
const ALL_RIGHTS = 0x1fffffffn;
const decoder = new TextDecoder();
const encoder = new TextEncoder();

/** A file tree persisted to `sql` (a Durable Object's `ctx.storage.sql`). */
export class SqliteFiles {
  constructor(sql) {
    this.sql = sql;
    sql.exec("CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, data BLOB)");
    // path -> { dir: true } | { data: Uint8Array }
    this.nodes = new Map([["/", { dir: true }]]);
    for (const row of sql.exec("SELECT path, data FROM files").toArray()) {
      this.ensureParents(row.path);
      this.nodes.set(row.path, row.data === null ? { dir: true } : { data: new Uint8Array(row.data) });
    }
  }

  ensureParents(path) {
    for (let p = parentOf(path); !this.nodes.has(p); p = parentOf(p)) this.nodes.set(p, { dir: true });
  }

  saveFile(path) {
    const node = this.nodes.get(path);
    if (node && !node.dir) this.sql.exec("INSERT OR REPLACE INTO files (path, data) VALUES (?, ?)", path, node.data);
  }

  saveDirectory(path) {
    this.sql.exec("INSERT OR REPLACE INTO files (path, data) VALUES (?, NULL)", path);
  }

  remove(path) {
    this.nodes.delete(path);
    this.sql.exec("DELETE FROM files WHERE path = ?", path);
  }

  children(path) {
    const prefix = path === "/" ? "/" : path + "/";
    const names = [];
    for (const p of this.nodes.keys()) {
      if (p !== "/" && p.startsWith(prefix) && !p.slice(prefix.length).includes("/")) names.push(p.slice(prefix.length));
    }
    return names.sort();
  }
}

function parentOf(path) {
  const i = path.lastIndexOf("/");
  return i <= 0 ? "/" : path.slice(0, i);
}

/** `relative` resolved against the directory `base`, normalized. */
function resolve(base, relative) {
  const parts = relative.startsWith("/") ? [] : base.split("/").filter(Boolean);
  for (const part of relative.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") parts.pop(); else parts.push(part);
  }
  return "/" + parts.join("/");
}

/**
 * The `wasi_snapshot_preview1` imports for one instance. `memory()` gives the
 * instance's memory once it exists; `log` takes what the guest writes to
 * stdout and stderr.
 */
export function wasiImports(files, memory, log) {
  const view = () => new DataView(memory().buffer);
  const bytes = () => new Uint8Array(memory().buffer);
  const text = (ptr, len) => decoder.decode(bytes().slice(ptr, ptr + len));
  // fd -> { path, dir, position, append, dirty, listing }
  const fds = new Map([[PREOPEN_FD, { path: "/", dir: true, position: 0 }]]);
  let nextFD = PREOPEN_FD + 1;
  const pending = { 1: "", 2: "" };

  const resolveAt = (fd, ptr, len) => {
    const entry = fds.get(fd);
    if (!entry) return { error: EBADF };
    if (!entry.dir) return { error: ENOTDIR };
    return { path: resolve(entry.path, text(ptr, len)) };
  };
  const writeFilestat = (ptr, path, node) => {
    const v = view();
    for (let i = 0; i < 64; i += 8) v.setBigUint64(ptr + i, 0n, true);
    v.setBigUint64(ptr, 1n, true);
    v.setBigUint64(ptr + 8, BigInt(hash(path)), true);
    v.setUint8(ptr + 16, node.dir ? DIRECTORY : REGULAR_FILE);
    v.setBigUint64(ptr + 24, 1n, true);
    v.setBigUint64(ptr + 32, BigInt(node.dir ? 0 : node.data.length), true);
  };
  const iovecs = (ptr, count) => {
    const v = view(), out = [];
    for (let i = 0; i < count; i++) out.push([v.getUint32(ptr + i * 8, true), v.getUint32(ptr + i * 8 + 4, true)]);
    return out;
  };
  const close = (entry) => {
    if (entry.dirty) { files.saveFile(entry.path); entry.dirty = false; }
  };

  return {
    args_get: () => SUCCESS,
    args_sizes_get: (countPtr, sizePtr) => { view().setUint32(countPtr, 0, true); view().setUint32(sizePtr, 0, true); return SUCCESS; },
    environ_get: () => SUCCESS,
    environ_sizes_get: (countPtr, sizePtr) => { view().setUint32(countPtr, 0, true); view().setUint32(sizePtr, 0, true); return SUCCESS; },
    clock_res_get: (_id, ptr) => { view().setBigUint64(ptr, 1000000n, true); return SUCCESS; },
    clock_time_get: (_id, _precision, ptr) => {
      view().setBigUint64(ptr, BigInt(Date.now()) * 1000000n, true);
      return SUCCESS;
    },
    random_get: (ptr, len) => {
      for (let offset = 0; offset < len; offset += 65536) {
        crypto.getRandomValues(bytes().subarray(ptr + offset, ptr + Math.min(len, offset + 65536)));
      }
      return SUCCESS;
    },
    poll_oneoff: (_in, _out, _count, eventsPtr) => { view().setUint32(eventsPtr, 0, true); return SUCCESS; },
    proc_exit: (code) => { throw new Error(`the node exited (${code})`); },

    fd_prestat_get: (fd, ptr) => {
      if (fd !== PREOPEN_FD) return EBADF;
      view().setUint8(ptr, 0);
      view().setUint32(ptr + 4, 1, true);
      return SUCCESS;
    },
    fd_prestat_dir_name: (fd, ptr, len) => {
      if (fd !== PREOPEN_FD) return EBADF;
      bytes().set(encoder.encode("/").slice(0, len), ptr);
      return SUCCESS;
    },
    fd_fdstat_get: (fd, ptr) => {
      const v = view();
      const entry = fds.get(fd);
      if (fd <= 2) v.setUint8(ptr, CHARACTER_DEVICE);
      else if (entry) v.setUint8(ptr, entry.dir ? DIRECTORY : REGULAR_FILE);
      else return EBADF;
      v.setUint16(ptr + 2, entry && entry.append ? FDFLAG_APPEND : 0, true);
      v.setBigUint64(ptr + 8, ALL_RIGHTS, true);
      v.setBigUint64(ptr + 16, ALL_RIGHTS, true);
      return SUCCESS;
    },
    fd_fdstat_set_flags: () => SUCCESS,
    fd_filestat_get: (fd, ptr) => {
      const entry = fds.get(fd);
      if (!entry) return fd <= 2 ? SUCCESS : EBADF;
      const node = files.nodes.get(entry.path);
      if (!node) return ENOENT;
      writeFilestat(ptr, entry.path, node);
      return SUCCESS;
    },
    fd_filestat_set_times: () => SUCCESS,
    fd_sync: (fd) => { const entry = fds.get(fd); if (entry) close(entry); return SUCCESS; },
    fd_close: (fd) => {
      const entry = fds.get(fd);
      if (!entry) return EBADF;
      close(entry);
      if (fd !== PREOPEN_FD) fds.delete(fd);
      return SUCCESS;
    },
    fd_seek: (fd, offset, whence, resultPtr) => {
      const entry = fds.get(fd);
      if (!entry || entry.dir) return EBADF;
      const size = files.nodes.get(entry.path).data.length;
      const base = whence === 0 ? 0 : whence === 1 ? entry.position : size;
      const position = base + Number(offset);
      if (position < 0) return EINVAL;
      entry.position = position;
      view().setBigUint64(resultPtr, BigInt(position), true);
      return SUCCESS;
    },
    fd_read: (fd, iovsPtr, iovsLen, readPtr) => {
      const entry = fds.get(fd);
      if (!entry || entry.dir) return EBADF;
      const data = files.nodes.get(entry.path).data;
      let total = 0;
      for (const [buf, len] of iovecs(iovsPtr, iovsLen)) {
        const chunk = data.subarray(entry.position, entry.position + len);
        bytes().set(chunk, buf);
        entry.position += chunk.length; total += chunk.length;
        if (chunk.length < len) break;
      }
      view().setUint32(readPtr, total, true);
      return SUCCESS;
    },
    fd_pread: (fd, iovsPtr, iovsLen, offset, readPtr) => {
      const entry = fds.get(fd);
      if (!entry || entry.dir) return EBADF;
      const data = files.nodes.get(entry.path).data;
      let position = Number(offset), total = 0;
      for (const [buf, len] of iovecs(iovsPtr, iovsLen)) {
        const chunk = data.subarray(position, position + len);
        bytes().set(chunk, buf);
        position += chunk.length; total += chunk.length;
        if (chunk.length < len) break;
      }
      view().setUint32(readPtr, total, true);
      return SUCCESS;
    },
    fd_write: (fd, iovsPtr, iovsLen, writtenPtr) => {
      let total = 0;
      if (fd === 1 || fd === 2) {
        for (const [buf, len] of iovecs(iovsPtr, iovsLen)) { pending[fd] += text(buf, len); total += len; }
        const lines = pending[fd].split("\n");
        pending[fd] = lines.pop();
        for (const line of lines) log(line);
        // stderr unbuffered: a fatal error's message comes just before its trap.
        if (fd === 2 && pending[fd]) { log(pending[fd]); pending[fd] = ""; }
        view().setUint32(writtenPtr, total, true);
        return SUCCESS;
      }
      const entry = fds.get(fd);
      if (!entry || entry.dir) return EBADF;
      const node = files.nodes.get(entry.path);
      for (const [buf, len] of iovecs(iovsPtr, iovsLen)) {
        const start = entry.append ? node.data.length : entry.position;
        if (start + len > node.data.length) {
          const grown = new Uint8Array(Math.max(start + len, node.data.length * 2));
          grown.set(node.data);
          node.data = grown.subarray(0, start + len);
        }
        node.data.set(bytes().subarray(buf, buf + len), start);
        entry.position = start + len; total += len;
      }
      node.data = node.data.slice(0, node.data.length);
      entry.dirty = true;
      view().setUint32(writtenPtr, total, true);
      return SUCCESS;
    },
    fd_readdir: (fd, bufPtr, bufLen, cookie, usedPtr) => {
      const entry = fds.get(fd);
      if (!entry || !entry.dir) return EBADF;
      const names = [".", "..", ...files.children(entry.path)];
      let used = 0;
      for (let i = Number(cookie); i < names.length; i++) {
        const name = encoder.encode(names[i]);
        const child = i < 2 ? { dir: true } : files.nodes.get(entry.path === "/" ? "/" + names[i] : entry.path + "/" + names[i]);
        const header = new DataView(new ArrayBuffer(24));
        header.setBigUint64(0, BigInt(i + 1), true);
        header.setBigUint64(8, BigInt(i + 2), true);
        header.setUint32(16, name.length, true);
        header.setUint8(20, child && child.dir ? DIRECTORY : REGULAR_FILE);
        const record = new Uint8Array(24 + name.length);
        record.set(new Uint8Array(header.buffer), 0);
        record.set(name, 24);
        const room = bufLen - used;
        bytes().set(record.subarray(0, Math.min(room, record.length)), bufPtr + used);
        used += Math.min(room, record.length);
        if (used >= bufLen) break;
      }
      view().setUint32(usedPtr, used, true);
      return SUCCESS;
    },

    path_open: (fd, _dirflags, pathPtr, pathLen, oflags, _base, _inheriting, fdflags, resultPtr) => {
      const at = resolveAt(fd, pathPtr, pathLen);
      if (at.error) return at.error;
      let node = files.nodes.get(at.path);
      if (node && (oflags & O_CREAT) && (oflags & O_EXCL)) return EEXIST;
      if (!node) {
        if (!(oflags & O_CREAT)) return ENOENT;
        const parent = files.nodes.get(parentOf(at.path));
        if (!parent) return ENOENT;
        if (!parent.dir) return ENOTDIR;
        node = { data: new Uint8Array(0) };
        files.nodes.set(at.path, node);
      }
      if ((oflags & O_DIRECTORY) && !node.dir) return ENOTDIR;
      if (node.dir && (oflags & O_TRUNC)) return EISDIR;
      const entry = { path: at.path, dir: !!node.dir, position: 0, append: !!(fdflags & FDFLAG_APPEND), dirty: false };
      if (!node.dir && (oflags & O_TRUNC)) { node.data = new Uint8Array(0); entry.dirty = true; }
      if (!node.dir && (oflags & O_CREAT)) entry.dirty = true;
      const newFD = nextFD++;
      fds.set(newFD, entry);
      view().setUint32(resultPtr, newFD, true);
      return SUCCESS;
    },
    path_filestat_get: (fd, _flags, pathPtr, pathLen, ptr) => {
      const at = resolveAt(fd, pathPtr, pathLen);
      if (at.error) return at.error;
      const node = files.nodes.get(at.path);
      if (!node) return ENOENT;
      writeFilestat(ptr, at.path, node);
      return SUCCESS;
    },
    path_filestat_set_times: () => SUCCESS,
    path_create_directory: (fd, pathPtr, pathLen) => {
      const at = resolveAt(fd, pathPtr, pathLen);
      if (at.error) return at.error;
      if (files.nodes.has(at.path)) return EEXIST;
      const parent = files.nodes.get(parentOf(at.path));
      if (!parent) return ENOENT;
      if (!parent.dir) return ENOTDIR;
      files.nodes.set(at.path, { dir: true });
      files.saveDirectory(at.path);
      return SUCCESS;
    },
    path_remove_directory: (fd, pathPtr, pathLen) => {
      const at = resolveAt(fd, pathPtr, pathLen);
      if (at.error) return at.error;
      const node = files.nodes.get(at.path);
      if (!node) return ENOENT;
      if (!node.dir) return ENOTDIR;
      if (files.children(at.path).length) return ENOTEMPTY;
      files.remove(at.path);
      return SUCCESS;
    },
    path_unlink_file: (fd, pathPtr, pathLen) => {
      const at = resolveAt(fd, pathPtr, pathLen);
      if (at.error) return at.error;
      const node = files.nodes.get(at.path);
      if (!node) return ENOENT;
      if (node.dir) return EISDIR;
      files.remove(at.path);
      return SUCCESS;
    },
    path_rename: (fd, oldPtr, oldLen, newFD, newPtr, newLen) => {
      const from = resolveAt(fd, oldPtr, oldLen), to = resolveAt(newFD, newPtr, newLen);
      if (from.error || to.error) return from.error || to.error;
      const node = files.nodes.get(from.path);
      if (!node) return ENOENT;
      if (node.dir) return ENOTSUP;
      files.remove(from.path);
      files.nodes.set(to.path, node);
      files.saveFile(to.path);
      return SUCCESS;
    },
    path_link: () => ENOTSUP,
    path_symlink: () => ENOTSUP,
    path_readlink: () => EINVAL,
  };
}

function hash(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 16777619) >>> 0;
  return h || 1;
}

export { ENOSYS };
