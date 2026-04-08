#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const versionFile = 'VERSION';
const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const jsonTargets = [
  {
    relPath: 'packages/signet-core/package.json',
    apply(data, version) {
      data.version = version;
    },
  },
  {
    relPath: 'packages/signet-mcp/package.json',
    apply(data, version) {
      data.version = version;
      data.dependencies['@signet-auth/core'] = `^${version}`;
    },
  },
  {
    relPath: 'packages/signet-mcp-server/package.json',
    apply(data, version) {
      data.version = version;
      data.dependencies['@signet-auth/core'] = `^${version}`;
    },
  },
  {
    relPath: 'packages/signet-mcp-tools/package.json',
    apply(data, version) {
      data.version = version;
      data.dependencies['@signet-auth/core'] = `^${version}`;
    },
  },
  {
    relPath: 'packages/signet-vercel-ai/package.json',
    apply(data, version) {
      data.version = version;
      data.dependencies['@signet-auth/core'] = `^${version}`;
    },
  },
  {
    relPath: 'packages/signet-mcp-tools/server.json',
    apply(data, version) {
      data.version = version;
      if (!Array.isArray(data.packages) || data.packages.length === 0) {
        throw new Error('Expected packages[0] in MCP server metadata.');
      }

      data.packages[0].version = version;
    },
  },
  {
    relPath: 'plugins/codex/package.json',
    apply(data, version) {
      data.version = version;
    },
  },
  {
    relPath: 'plugins/claude-code/package.json',
    apply(data, version) {
      data.version = version;
    },
  },
  {
    relPath: 'package-lock.json',
    apply(data, version) {
      const packageEntries = [
        'packages/signet-core',
        'packages/signet-mcp',
        'packages/signet-mcp-server',
        'packages/signet-mcp-tools',
        'packages/signet-vercel-ai',
      ];

      for (const packagePath of packageEntries) {
        const entry = data.packages?.[packagePath];
        if (!entry) {
          throw new Error(`Expected ${packagePath} entry in package-lock.json.`);
        }

        entry.version = version;
      }

      for (const packagePath of packageEntries.slice(1)) {
        const entry = data.packages?.[packagePath];
        if (!entry.dependencies?.['@signet-auth/core']) {
          throw new Error(`Expected @signet-auth/core dependency in ${packagePath}.`);
        }

        entry.dependencies['@signet-auth/core'] = `^${version}`;
      }
    },
  },
];

const textTargets = [
  {
    relPath: 'crates/signet-core/Cargo.toml',
    apply(content, version) {
      return replacePackageVersion(content, version, 'crates/signet-core/Cargo.toml');
    },
  },
  {
    relPath: 'signet-cli/Cargo.toml',
    apply(content, version) {
      let next = replacePackageVersion(content, version, 'signet-cli/Cargo.toml');
      next = replaceChecked(
        next,
        /(signet-core\s*=\s*\{\s*version\s*=\s*)"[^"]+"/,
        `$1"${version}"`,
        'signet-cli signet-core dependency version',
      );
      return next;
    },
  },
  {
    relPath: 'bindings/signet-ts/Cargo.toml',
    apply(content, version) {
      return replacePackageVersion(content, version, 'bindings/signet-ts/Cargo.toml');
    },
  },
  {
    relPath: 'bindings/signet-py/Cargo.toml',
    apply(content, version) {
      return replacePackageVersion(content, version, 'bindings/signet-py/Cargo.toml');
    },
  },
  {
    relPath: 'bindings/signet-py/pyproject.toml',
    apply(content, version) {
      return replaceSectionVersion(content, 'project', version, 'bindings/signet-py/pyproject.toml');
    },
  },
  {
    relPath: 'bindings/signet-py/src/lib.rs',
    apply(content, version) {
      return replaceChecked(
        content,
        /(m\.add\("__version__",\s*)"[^"]+"/,
        `$1"${version}"`,
        'bindings/signet-py __version__',
      );
    },
  },
  {
    relPath: 'packages/signet-mcp-tools/src/tools.ts',
    apply(content, version) {
      return replaceChecked(
        content,
        /(name:\s*'signet-mcp-tools',\s*version:\s*)'[^']+'/,
        `$1'${version}'`,
        'packages/signet-mcp-tools runtime version',
      );
    },
  },
];

function main() {
  const [command = 'check', ...args] = process.argv.slice(2);

  switch (command) {
    case 'check':
      runCheck(args);
      break;
    case 'sync':
      runSync(readVersion());
      break;
    case 'set':
      runSet(args[0]);
      break;
    case 'help':
    case '--help':
    case '-h':
      printUsage();
      break;
    default:
      fail(`Unknown command: ${command}`);
  }
}

function runCheck(args) {
  const version = readVersion();
  const tag = parseTagArg(args);
  const outOfSync = listOutOfSync(version);

  if (tag) {
    const expectedTag = `v${version}`;
    if (tag !== expectedTag) {
      outOfSync.push(`${versionFile} (expected tag ${expectedTag}, got ${tag})`);
    }
  }

  if (outOfSync.length > 0) {
    console.error(`Version check failed for ${version}.`);
    for (const relPath of outOfSync) {
      console.error(`- ${relPath}`);
    }
    process.exit(1);
  }

  console.log(`All managed version fields match ${version}.`);
}

function runSync(version) {
  const updated = [];

  for (const target of [...jsonTargets, ...textTargets]) {
    const current = readRepoFile(target.relPath);
    const next = renderTarget(target, version);
    if (current !== next) {
      writeRepoFile(target.relPath, next);
      updated.push(target.relPath);
    }
  }

  if (updated.length === 0) {
    console.log(`All managed files already match ${version}.`);
    return;
  }

  console.log(`Synced ${updated.length} files to ${version}:`);
  for (const relPath of updated) {
    console.log(`- ${relPath}`);
  }
}

function runSet(nextVersion) {
  if (!nextVersion) {
    fail('Usage: node scripts/version-sync.mjs set <version>');
  }
  if (!semverPattern.test(nextVersion)) {
    fail(`Invalid version "${nextVersion}". Expected a semantic version like 0.4.6.`);
  }

  writeRepoFile(versionFile, `${nextVersion}\n`);
  console.log(`Updated ${versionFile} to ${nextVersion}.`);
  runSync(nextVersion);
}

function parseTagArg(args) {
  const tagIndex = args.indexOf('--tag');
  if (tagIndex === -1) {
    return null;
  }

  const value = args[tagIndex + 1];
  if (!value) {
    fail('Expected a value after --tag.');
  }

  return value.startsWith('refs/tags/') ? value.slice('refs/tags/'.length) : value;
}

function listOutOfSync(version) {
  const outOfSync = [];

  for (const target of [...jsonTargets, ...textTargets]) {
    const current = readRepoFile(target.relPath);
    const expected = renderTarget(target, version);
    if (current !== expected) {
      outOfSync.push(target.relPath);
    }
  }

  return outOfSync;
}

function renderTarget(target, version) {
  const current = readRepoFile(target.relPath);

  if (jsonTargets.includes(target)) {
    const data = JSON.parse(current);
    target.apply(data, version);
    return `${JSON.stringify(data, null, 2)}\n`;
  }

  return target.apply(current, version);
}

function readVersion() {
  const version = readRepoFile(versionFile).trim();
  if (!semverPattern.test(version)) {
    fail(`Invalid ${versionFile} value "${version}".`);
  }

  return version;
}

function replacePackageVersion(content, version, label) {
  return replaceChecked(
    content,
    /(^\[package\][\s\S]*?^version\s*=\s*)"[^"]+"/m,
    `$1"${version}"`,
    `${label} package version`,
  );
}

function replaceSectionVersion(content, sectionName, version, label) {
  const escapedSection = sectionName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(^\\[${escapedSection}\\][\\s\\S]*?^version\\s*=\\s*)"[^"]+"`, 'm');
  return replaceChecked(content, pattern, `$1"${version}"`, `${label} ${sectionName} version`);
}

function replaceChecked(content, pattern, replacement, label) {
  let matched = false;
  const next = content.replace(pattern, (...args) => {
    matched = true;
    if (typeof replacement === 'function') {
      return replacement(...args);
    }
    return replacement.replace(/\$(\d+)/g, (_, index) => args[Number(index)] ?? '');
  });

  if (!matched) {
    throw new Error(`Could not update ${label}.`);
  }

  return next;
}

function readRepoFile(relPath) {
  return readFileSync(path.join(repoRoot, relPath), 'utf8');
}

function writeRepoFile(relPath, contents) {
  writeFileSync(path.join(repoRoot, relPath), contents);
}

function printUsage() {
  console.log(`Usage:
  node scripts/version-sync.mjs check [--tag v0.4.5]
  node scripts/version-sync.mjs sync
  node scripts/version-sync.mjs set <version>`);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

main();
