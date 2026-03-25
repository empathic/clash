/**
 * Virtual filesystem for the Clash interactive tutorial.
 * Simulates a project directory and user home with sensitive files.
 */

const FILES = {
  '/project/.git/config': '[core]\n  repositoryformatversion = 0\n  bare = false\n',
  '/project/.git/HEAD': 'ref: refs/heads/main\n',
  '/project/.git/refs/heads/main': 'a1b2c3d4e5f6\n',
  '/project/src/main.rs': 'use my_project::run;\n\nfn main() {\n    run();\n}\n',
  '/project/src/lib.rs': 'pub mod utils;\n\npub fn run() {\n    println!("Hello, world!");\n}\n',
  '/project/src/utils/helpers.rs': 'pub fn format_name(name: &str) -> String {\n    name.trim().to_lowercase()\n}\n',
  '/project/tests/integration_test.rs': '#[test]\nfn test_run() {\n    my_project::run();\n}\n',
  '/project/Cargo.toml': '[package]\nname = "my-project"\nversion = "0.1.0"\nedition = "2021"\n',
  '/project/Cargo.lock': '# This file is auto-generated\n',
  '/project/README.md': '# My Project\n\nA sample Rust project.\n',
  '/project/.gitignore': '/target\n*.swp\n.env\n',
  '/home/user/.ssh/id_rsa': '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...[REDACTED]\n-----END OPENSSH PRIVATE KEY-----\n',
  '/home/user/.ssh/id_rsa.pub': 'ssh-rsa AAAAB3NzaC1yc2E... user@machine\n',
  '/home/user/.gitconfig': '[user]\n  name = Demo User\n  email = demo@example.com\n',
  '/home/user/secrets.env': 'API_KEY=sk-live-xxxxxxxxxxxx\nDATABASE_URL=postgres://admin:password@prod.db\n',
};

export class VirtualFS {
  constructor() {
    this.files = new Map(Object.entries(FILES));
  }

  exists(path) {
    if (this.files.has(path)) return true;
    const prefix = path.endsWith('/') ? path : path + '/';
    for (const key of this.files.keys()) {
      if (key.startsWith(prefix)) return true;
    }
    return false;
  }

  read(path) {
    return this.files.get(path) || null;
  }

  isDir(path) {
    const prefix = path.endsWith('/') ? path : path + '/';
    for (const key of this.files.keys()) {
      if (key.startsWith(prefix)) return true;
    }
    return false;
  }

  ls(dirPath) {
    const prefix = dirPath.endsWith('/') ? dirPath : dirPath + '/';
    const entries = new Set();
    for (const key of this.files.keys()) {
      if (key.startsWith(prefix)) {
        const rest = key.slice(prefix.length);
        const firstPart = rest.split('/')[0];
        if (firstPart) entries.add(firstPart);
      }
    }
    return [...entries].sort();
  }

  glob(pattern, basePath = '/project') {
    const prefix = basePath.endsWith('/') ? basePath : basePath + '/';
    const matches = [];
    for (const key of this.files.keys()) {
      if (!key.startsWith(prefix)) continue;
      const relative = key.slice(prefix.length);
      if (this._matchGlob(relative, pattern)) {
        matches.push(key);
      }
    }
    return matches.sort();
  }

  isInside(filePath, dirPath) {
    const dir = dirPath.endsWith('/') ? dirPath : dirPath + '/';
    return filePath === dirPath || filePath.startsWith(dir);
  }

  getAllPaths() {
    return [...this.files.keys()].sort();
  }

  _matchGlob(str, pattern) {
    const regex = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '\0')
      .replace(/\*/g, '[^/]*')
      .replace(/\0/g, '.*')
      .replace(/\?/g, '[^/]');
    return new RegExp('^' + regex + '$').test(str);
  }
}
