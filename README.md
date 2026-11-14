# 依赖漏洞影响分析器

纯前端、离线的依赖漏洞影响分析工具。原生 TypeScript + Vite，无 UI 框架。

导入 `package-lock.json` / `poetry.lock` / `Cargo.lock` 与本地 OSV 格式漏洞库，
得到：受影响的包、漏洞从哪条依赖路径进来、最小升级方案、以及升级后是否会引入冲突。

## 快速开始

```bash
npm install
npm run dev        # 开发服务器
npm test           # 2400+ 条测试
npm run build      # 产出静态站点到 dist/
```

打开页面后点「载入内置示例」即可看到三套边界用例的完整结果。

## 三个生态的版本语义（各自独立实现）

| | npm | Cargo | PyPI |
|---|---|---|---|
| 区间语法 | node-semver 7.x | Rust `semver` crate 1.0 | poetry-core / PEP 440 |
| 裸版本 | 精确 / x-range | **caret**（`1.2` ≡ `^1.2`） | （poetry）精确 |
| 部分版本 | `1.2` = `1.2.x` | `1.2` = `>=1.2.0,<1.3.0` | `1.2.*` 才是通配 |
| 预发布 | 需同 major.minor.patch 的 comparator 放行 | 同上 | dev < pre < 正式 < post |
| 特殊 | `^0.0.3` 只到 `0.0.3`；x-range 上界带 `-0` | 不支持 `\|\|` / 连字符区间 / `v` 前缀 | epoch、local 段、`~=`、last_affected 闭区间 |

实现不是“读文档推测”，而是逐分支复刻参考实现，并用实测用例锁定：

- `src/test/parity.test.ts`：118 条期望值由 node-semver 7.8 与 Rust semver crate 1.0.28 **实际运行**取得。
- `src/test/py-parity.test.ts`：1512 条由 poetry-core 2.5 **实际运行**取得。
- `src/test/spec-parity.test.ts`：762 条由 `packaging` **实际运行**取得。

## OSV 区间求值

严格按 OSV schema 的伪代码实现（`src/core/osv/osv-range.ts`）：

1. `limit` 只决定该 range 是否参与评估；
2. 事件按版本排序后遍历，`introduced` 在 `v >= x` 时置为受影响，`fixed` 在 `v >= x` 时清除，
   `last_affected` 在 `v > x` 时清除；
3. 预发布按生态排序参与比较（`1.2.3-rc.1 < 1.2.3`），**没有**额外的预发布门控。

注意这与“npm 区间表达式默认排除预发布”是两套规则，代码与文档里都分开处理。

## 分析输出

- **命中依据**：给出具体区间（如 `2.0.0 ≤ v < 2.0.1`）或「affected.versions 精确清单」。
- **依赖路径**：从根到漏洞包的全部简单路径，按长度排序；可切换为 SVG 依赖图。路径解析用 Node
  的真实 `node_modules` 向上查找算法，能区分同名多副本。
- **最小升级方案**：
  - 候选版本来自锁文件中已有的副本 + OSV 的 `fixed` 边界；
  - 对**整库**检查候选是否仍受其它漏洞影响（只修好当前这条不算修好）；
  - 逐条检查所有入边约束，优先直接升级，其次连带升级父包，再次提示「需放宽根声明」；
  - 给出的目标是“能满足所有约束的最低修复版本”，不是最新版本。
- **冲突与未知**：
  - 升级后父约束检查逐条给出 ✓ / ✗ / ?；
  - 目标版本不在锁文件中时，其自身依赖未知 —— 明确标注，不假装算过；
  - `Cargo.lock` 不含声明区间，所有约束检查标为「无法验证」而不是默认通过；
  - 同一包被多个方案要求升到不同版本时给出跨方案冲突。

## 实测的边界用例（`fixtures/`）

- npm：`^0.0.3` 只接受 `0.0.3`，修复需放宽根声明；`pre-core` 的 `fixed` 是预发布 `1.2.3-beta.10`，
  `beta.4` 受影响而 `beta.10` 不受影响（数值比较）；`ansi-regex` 当前版本恰好等于 `fixed`，不误报；
  父包 `pinner` 精确锁定 `leaf@2.0.0`，必须连带升父包；`blocker` 精确锁死且无更高版本 → 无解。
- Python：`ansible-base@2.10.0rc1` 落在 `[2.10.0rc1, 2.10.0)`；`~=2.10.0rc1` 接受 `2.10.0`；
  `PyYAML@5.4.1` 的 `last_affected` 是闭区间且无 `fixed` → 拿不到修复版本；
  `idna@3.0.1+local` 的 local 段参与排序。
- Cargo：同一 crate 有 `syn 1.0.109` 与 `2.0.0`，只有前者命中；`powerfmt@0.2.0-rc.2` 落在
  `[0.2.0-rc.1, 0.2.0)`；`serde` 走 `affected.versions` 精确清单路径。

## 目录结构

```
src/core/versions/   三套版本语义（semver-core / npm-range / cargo-req / pep440 / py-constraint）
src/core/osv/        OSV schema 校验与事件流求值
src/core/parsers/    三份锁文件解析 → 统一依赖图
src/core/analysis/   漏洞匹配、路径回溯、CVSS 分级
src/core/upgrade/    最小升级规划与影响模拟
src/ui/              无框架 DOM 渲染、SVG 依赖图、示例数据
src/test/            2456 条测试（含与官方实现的对拍语料）
fixtures/            验证用的漏洞库与三份锁文件
```
