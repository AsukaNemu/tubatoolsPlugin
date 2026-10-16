# 图吧工具箱社区插件库

这是[图吧工具箱 WinUI 3](https://github.com/luolangaga/Tubas)的社区资源仓库，用于收集和分发实用的 Windows 工具，并展示社区成员提交的电脑性能报告。

## 仓库内容

| 路径 | 说明 |
| --- | --- |
| [`plugins/`](plugins/) | 社区工具。每个工具使用独立目录保存 `plugin.json`、压缩包和图标等文件 |
| [`reports/`](reports/) | 社区成员提交的性能报告及延迟测试图片 |
| [`rules/malware.yar`](rules/malware.yar) | 插件安全扫描使用的 YARA 规则 |
| [`scripts/`](scripts/) | 元数据、压缩包可用性和资源下载校验脚本 |
| [`.github/workflows/`](.github/workflows/) | 插件审核、病毒扫描和排行榜生成流程 |

排行榜和社区工具索引由 GitHub Actions 手动生成，生成文件为仓库根目录下的 `leaderboard.json`、`leaderboard/details/` 和 `plugins-index.json`。

## 提交社区工具

### 1. 准备文件

在 `plugins/<分类>/<工具目录>/` 下创建工具目录。目录名建议使用小写英文、数字和连字符，避免空格和特殊字符。通常至少包含：

```text
plugins/
└── 其他工具/
    └── example-tool/
        ├── plugin.json
        ├── ExampleTool.zip
        └── icon.png
```

压缩包应包含可运行的工具文件，不要提交无关的安装器、个人文件或敏感信息。请确认工具来源可靠，并在提交前自行检查文件安全性。

### 2. 填写 `plugin.json`

最小示例：

```json
{
  "id": "example-tool",
  "name": "Example Tool",
  "version": "1.0.0",
  "description": "工具简介",
  "category": "其他工具",
  "tags": ["Windows"],
  "launchTarget": "ExampleTool.exe",
  "author": "你的 GitHub 用户名",
  "homepage": "https://example.com",
  "file": "ExampleTool.zip",
  "icon": "icon.png"
}
```

必填字段为 `id`、`name` 和 `category`。常用字段说明：

| 字段 | 说明 |
| --- | --- |
| `id` | 全局唯一标识，只能使用字母、数字、下划线和连字符 |
| `name` | 工具显示名称 |
| `version` | 工具版本，建议使用 `主版本.次版本.修订版本` 格式 |
| `description` | 简短、准确的功能介绍 |
| `category` | 工具分类，须与现有分类保持一致 |
| `tags` | 便于搜索的标签数组 |
| `launchTarget` | 压缩包内要启动的文件；包含多个可执行文件时建议填写 |
| `file` | 同目录下的 ZIP 文件名；也可以使用 `downloadUrl` 指向外部下载地址 |
| `icon` | 压缩包内的图标文件名，支持 PNG、ICO、JPG、JPEG 和 SVG |
| `archVariants` | 可选的架构变体数组，架构值支持 `x86`、`x64` 和 `ARM64` |

请不要重复使用已有的 `id`，并确保 `file`、`icon` 和 `launchTarget` 的路径与实际压缩包内容一致。

### 3. 使用客户端提交

请使用图吧工具箱客户端中的图形化社区提交功能，不需要手动创建分支、执行 Git 命令或上传 Pull Request：

1. 打开客户端的社区提交页面，选择“提交工具”。
2. 按页面提示填写工具信息，选择工具压缩包和图标文件。
3. 提交前确认 `plugin.json` 中的字段、文件名和启动目标正确。
4. 点击提交，客户端会自动完成仓库提交和 Pull Request 创建。
5. 等待自动检查和维护者审核。扫描通过不代表一定会合并，维护者仍会进行人工复核。

如需触发病毒扫描，请在生成的 Pull Request 评论区发送 `@tubabot review`；通常客户端会提示对应的提交状态和审核链接。

## 本地校验

校验元数据：

```bash
python3 scripts/validate-metadata.py plugins/其他工具/example-tool/plugin.json
```

校验 ZIP 内容、启动文件和图标：

```bash
python3 scripts/validate-usability.py \
  plugins/其他工具/example-tool/plugin.json \
  plugins/其他工具/example-tool
```

两个脚本都会输出 JSON 结果。`status` 为 `pass` 表示未发现阻止提交的问题；`warnings` 仍建议在创建 Pull Request 前处理。

审核脚本的离线回归检查：

```bash
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

病毒审核会记录文件收集与各扫描器的退出状态。下载不完整、扫描器失败、零文件扫描、
VirusTotal 查询失败或未收录的文件均不能获得 `verified`；未配置 VirusTotal 时会明确标为
跳过。扫描只验证对应提交，PR 更新后需要重新扫描。脚本测试使用合成数据和模拟响应，
不会执行插件或向 VirusTotal 上传文件。

## 提交性能报告

性能报告请通过客户端中的图形化报告提交功能上传，不要手动修改 `reports/` 目录或操作 Git。报告应包含真实硬件和测试结果；请勿提交姓名、序列号、激活码、账号信息等隐私或敏感数据。报告合入后，维护者可以在 Actions 页面手动运行 **Update leaderboard & community index**，更新排行榜和工具索引。

## 安全说明

社区工具来自第三方，使用前请自行确认来源和用途。仓库的自动流程会使用 ClamAV、YARA 和可选的 VirusTotal 对 Pull Request 中的文件进行扫描；任何扫描结果都不能替代用户对软件的最终判断。
