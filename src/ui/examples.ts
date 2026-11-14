/**
 * 示例数据：页面内置一套“故意踩边界”的演示工程，方便不上传文件也能看懂工具在做什么。
 * 内容与 fixtures/ 下的文件保持一致（测试也使用同一批数据），
 * 因此这里展示的结果与实际分析路径完全相同。
 */

export interface ExampleFile {
  readonly filename: string
  readonly text: string
}

export const EXAMPLE_OSV = `[
  {
    "id": "GHSA-TEST-NPM-PRECORE",
    "summary": "pre-core 在 1.2.3-beta.10 之前存在原型污染",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "pre-core" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": "1.2.3-beta.10" }] }]
    }]
  },
  {
    "id": "GHSA-TEST-NPM-ZERO",
    "summary": "zero 0.2.3 存在拒绝服务",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "zero" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0.2.3" }, { "fixed": "0.2.4" }] }]
    }]
  },
  {
    "id": "GHSA-TEST-NPM-TINY",
    "summary": "tiny 0.0.3 存在越界写",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "tiny" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0.0.3" }, { "fixed": "0.0.4" }] }]
    }]
  },
  {
    "id": "GHSA-TEST-NPM-LEAF",
    "summary": "leaf 2.0.0 单版本缺陷",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "leaf" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "2.0.0" }, { "fixed": "2.0.1" }] }]
    }]
  },
  {
    "id": "GHSA-TEST-NPM-STUCK",
    "summary": "stuck 1.0.0 存在命令注入",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "stuck" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "1.0.0" }, { "fixed": "1.0.1" }] }]
    }]
  },
  {
    "id": "GHSA-TEST-NPM-ANSI",
    "summary": "ansi-regex 5.0.1 之前存在 ReDoS（对照用例：当前版本恰为修复版本）",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "ansi-regex" },
      "ranges": [
        { "type": "ECOSYSTEM", "events": [{ "introduced": "3.0.0" }, { "fixed": "5.0.1" }] },
        { "type": "ECOSYSTEM", "events": [{ "introduced": "6.0.0" }, { "fixed": "6.0.1" }] }
      ]
    }]
  },
  {
    "id": "GHSA-TEST-NPM-MIDDLE",
    "summary": "middle 1.0.0 存在信息泄露",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "middle" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "1.0.0" }, { "fixed": "1.1.0" }] }]
    }]
  },
  {
    "id": "GHSA-TEST-NPM-ISODD-DEV",
    "summary": "is-odd 3.0.1 存在开发依赖缺陷",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" }],
    "affected": [{
      "package": { "ecosystem": "npm", "name": "is-odd" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "3.0.0" }, { "fixed": "3.0.2" }] }]
    }]
  },
  {
    "id": "PYSEC-TEST-URLLIB3",
    "summary": "urllib3 1.26.5 之前存在请求走私",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N" }],
    "affected": [{
      "package": { "ecosystem": "PyPI", "name": "urllib3" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "1.26.0" }, { "fixed": "1.26.5" }] }]
    }]
  },
  {
    "id": "PYSEC-TEST-PYYAML",
    "summary": "PyYAML 5.4.1 及之前存在任意代码执行（last_affected 闭区间，无 fixed）",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    "affected": [{
      "package": { "ecosystem": "PyPI", "name": "PyYAML" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "5.4.0" }, { "last_affected": "5.4.1" }] }]
    }]
  },
  {
    "id": "PYSEC-TEST-ANSIBLE-BASE",
    "summary": "ansible-base 2.10.0rc1 存在模板注入（预发布版本落在区间内）",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N" }],
    "affected": [{
      "package": { "ecosystem": "PyPI", "name": "ansible-base" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "2.10.0rc1" }, { "fixed": "2.10.0" }] }]
    }]
  },
  {
    "id": "PYSEC-TEST-IDNA",
    "summary": "idna 3.0 ~ 3.1 之前存在规范化绕过（锁文件里是带 local 段的 3.0.1+local）",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N" }],
    "affected": [{
      "package": { "ecosystem": "PyPI", "name": "idna" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "3.0" }, { "fixed": "3.1" }] }]
    }]
  },
  {
    "id": "RUSTSEC-TEST-TIME",
    "summary": "time 0.3.37 之前存在本地拒绝服务",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" }],
    "affected": [{
      "package": { "ecosystem": "crates.io", "name": "time" },
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0.3.0" }, { "fixed": "0.3.37" }] }]
    }]
  },
  {
    "id": "RUSTSEC-TEST-SYN",
    "summary": "syn 1.x 在 1.0.110 之前存在解析器缺陷（锁文件同时有 1.0.109 与 2.0.0）",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L" }],
    "affected": [{
      "package": { "ecosystem": "crates.io", "name": "syn" },
      "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "1.0.0" }, { "fixed": "1.0.110" }] }]
    }]
  },
  {
    "id": "RUSTSEC-TEST-POWERFMT",
    "summary": "powerfmt 0.2.0-rc.1 存在格式化溢出（introduced 是预发布）",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" }],
    "affected": [{
      "package": { "ecosystem": "crates.io", "name": "powerfmt" },
      "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0.2.0-rc.1" }, { "fixed": "0.2.0" }] }]
    }]
  },
  {
    "id": "RUSTSEC-TEST-SERDE-LIST",
    "summary": "serde 1.0.193 出现在受影响版本清单中",
    "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" }],
    "affected": [{
      "package": { "ecosystem": "crates.io", "name": "serde" },
      "versions": ["1.0.193"],
      "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "1.0.190" }, { "fixed": "1.0.194" }] }]
    }]
  }
]
`

export const EXAMPLE_NPM_LOCK = `{
  "name": "edge-market",
  "version": "2.1.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "edge-market",
      "version": "2.1.0",
      "license": "MIT",
      "dependencies": {
        "ansi-regex": "^5.0.0",
        "blocker": "1.0.0",
        "chalk": "^5.3.0",
        "leaf": "^1.0.0",
        "left-pad": "^1.3.0",
        "middle": "*",
        "other-tool": "^1.0.0",
        "pinner": "^1.0.0",
        "pre-core": ">=1.2.3-beta.4 <1.3.0",
        "tiny": "^0.0.3",
        "zero": "^0.2.3"
      },
      "devDependencies": { "is-odd": "^3.0.1" }
    },
    "node_modules/ansi-regex": { "version": "5.0.1", "license": "MIT" },
    "node_modules/blocker": {
      "version": "1.0.0",
      "license": "MIT",
      "dependencies": { "stuck": "1.0.0" }
    },
    "node_modules/blocker/node_modules/stuck": { "version": "1.0.0", "license": "MIT" },
    "node_modules/chalk": {
      "version": "5.3.0",
      "license": "MIT",
      "dependencies": { "ansi-regex": "^6.0.0", "pre-core": "1.2.3-beta.10" }
    },
    "node_modules/chalk/node_modules/ansi-regex": { "version": "6.0.1", "license": "MIT" },
    "node_modules/chalk/node_modules/pre-core": { "version": "1.2.3-beta.10", "license": "MIT" },
    "node_modules/leaf": { "version": "1.0.0", "license": "MIT" },
    "node_modules/left-pad": { "version": "1.3.0", "license": "WTFPL" },
    "node_modules/middle": {
      "version": "1.0.0",
      "license": "MIT",
      "dependencies": { "leaf": "^1.0.0" }
    },
    "node_modules/other-tool": {
      "version": "1.0.0",
      "license": "MIT",
      "dependencies": { "leaf": "^2.0.0", "pinner": "^1.1.0" }
    },
    "node_modules/other-tool/node_modules/leaf": { "version": "2.1.0", "license": "MIT" },
    "node_modules/other-tool/node_modules/pinner": {
      "version": "1.1.0",
      "license": "MIT",
      "dependencies": { "leaf": "^2.0.0" }
    },
    "node_modules/other-tool/node_modules/pinner/node_modules/leaf": { "version": "2.1.0", "license": "MIT" },
    "node_modules/pinner": {
      "version": "1.0.0",
      "license": "MIT",
      "dependencies": { "leaf": "2.0.0" }
    },
    "node_modules/pinner/node_modules/leaf": { "version": "2.0.0", "license": "MIT" },
    "node_modules/pre-core": { "version": "1.2.3-beta.4", "license": "MIT" },
    "node_modules/tiny": { "version": "0.0.3", "license": "MIT" },
    "node_modules/zero": { "version": "0.2.3", "license": "MIT" },
    "node_modules/is-buffer": { "version": "2.0.5", "dev": true, "license": "MIT" },
    "node_modules/is-number": {
      "version": "6.0.0",
      "dev": true,
      "license": "MIT",
      "dependencies": { "is-buffer": "^2.0.0" }
    },
    "node_modules/is-odd": {
      "version": "3.0.1",
      "dev": true,
      "license": "MIT",
      "dependencies": { "is-number": "^6.0.0" }
    }
  }
}
`

export const EXAMPLE_CARGO_LOCK = `# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "edge-service"
version = "0.1.0"
dependencies = ["powerfmt", "serde", "syn 1.0.109", "syn 2.0.0", "time"]

[[package]]
name = "powerfmt"
version = "0.2.0-rc.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"

[[package]]
name = "syn"
version = "1.0.109"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6666666666666666666666666666666666666666666666666666666666666666"

[[package]]
name = "syn"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "7777777777777777777777777777777777777777777777777777777777777777"

[[package]]
name = "time"
version = "0.3.36"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8888888888888888888888888888888888888888888888888888888888888888"
dependencies = ["deranged", "num-conv", "powerfmt", "time-core"]

[[package]]
name = "deranged"
version = "0.3.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9999999999999999999999999999999999999999999999999999999999999999"
dependencies = ["powerfmt"]

[[package]]
name = "num-conv"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "time-core"
version = "0.1.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
`

export const EXAMPLE_POETRY_LOCK = `# This file is automatically @generated by Poetry 2.1.1 and should not be changed by hand.

[[package]]
name = "ansible-base"
version = "2.10.0rc1"
description = "Radically simple IT automation"
optional = false
python-versions = ">=3.6"
groups = ["main"]
files = []

[[package]]
name = "certifi"
version = "2020.12.5"
description = "Python package for providing Mozilla's CA Bundle."
optional = false
python-versions = "*"
groups = ["main"]
files = []

[[package]]
name = "charset-normalizer"
version = "2.0.12"
description = "The Real First Universal Charset Detector."
optional = false
python-versions = ">=3.5.0"
groups = ["main"]
files = []

[[package]]
name = "idna"
version = "3.0.1+local"
description = "Internationalized Domain Names in Applications (IDNA)"
optional = false
python-versions = ">=3.5"
groups = ["main"]
files = []

[[package]]
name = "pyyaml"
version = "5.4.1"
description = "YAML parser and emitter for Python"
optional = false
python-versions = ">=2.7"
groups = ["main"]
files = []

[[package]]
name = "requests"
version = "2.27.1"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=2.7"
groups = ["main"]
files = []

[package.dependencies]
certifi = ">=2017.4.17"
charset-normalizer = ">=2.0.0,<2.1.0"
idna = ">=2.5,<4"
urllib3 = ">=1.21.1,<1.27"

[[package]]
name = "urllib3"
version = "1.26.4"
description = "HTTP library with thread-safe connection pooling, file post, and more."
optional = false
python-versions = ">=2.7, <4"
groups = ["main"]
files = []

[metadata]
lock-version = "2.1"
python-versions = ">=3.8"
content-hash = "0000000000000000000000000000000000000000000000000000000000000000"
`

export const EXAMPLE_PYPROJECT = `[project]
name = "edge-service-py"
version = "0.1.0"
requires-python = ">=3.8"
dependencies = [
  "ansible-base~=2.10.0rc1",
  "PyYAML>=5.4.0,<6.0",
  "requests>=2.25,<3",
]

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
`

export const EXAMPLE_PROJECTS: { label: string; files: ExampleFile[] }[] = [
  {
    label: 'npm 演示工程（edge-market）',
    files: [{ filename: 'node/package-lock.json', text: EXAMPLE_NPM_LOCK }],
  },
  {
    label: 'Cargo 演示工程（edge-service）',
    files: [{ filename: 'rust/Cargo.lock', text: EXAMPLE_CARGO_LOCK }],
  },
  {
    label: 'Python 演示工程（edge-service-py）',
    files: [
      { filename: 'python/pyproject.toml', text: EXAMPLE_PYPROJECT },
      { filename: 'python/poetry.lock', text: EXAMPLE_POETRY_LOCK },
    ],
  },
]
