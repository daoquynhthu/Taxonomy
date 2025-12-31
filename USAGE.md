# EternalCore 指令使用文档 (EternalCore CLI Documentation)

EternalCore 是一个通用的数字资产持久化引擎，支持多语言、版本控制、加密压缩及元数据扩展。

## 1. 基础配置 (Basic Configuration)

默认根目录为当前目录下的数据文件夹，可以通过命令行参数覆盖：

- `--root`: 指定主存储根目录 (默认: `d:\Seed`)
- `--mirror`: 指定镜像备份目录 (可选)
- `--config`: 指定 JSON 配置文件路径 (可选)

## 2. 核心指令 (Core Commands)

### 2.1 初始化与维护
- **重建索引**: 当 Sidecar 元数据文件发生变化或数据库损坏时使用。
  ```bash
  python manager_v2.py rebuild
  ```
- **系统审计**: 验证所有数据的完整性、签名及 Merkle 状态。
  ```bash
  python manager_v2.py audit
  ```
- **健康检查**: 查看系统运行状态及磁盘空间。
  ```bash
  python manager_v2.py health
  ```

### 2.2 数据操作
- **添加条目 (多语言支持)**:
  ```bash
  # 示例：添加一个支持中英文的条目
  python manager_v2.py add --title '{"zh": "相对论", "en": "Relativity"}' --category "Science.Physics" --content '{"zh": "内容...", "en": "Content..."}'
  ```
- **查看条目**:
  ```bash
  python manager_v2.py list
  ```
- **版本回滚**: 将特定条目回滚到指定版本。
  ```bash
  python manager_v2.py rollback --id <ENTRY_ID> --version <VERSION_NUM>
  ```

## 3. 进阶功能 (Advanced Features)

### 3.1 依赖验证
- **验证依赖链**: 确保所有引用的依赖条目均存在。
  ```bash
  python manager_v2.py validate --id <ENTRY_ID>
  ```
- **可视化依赖图**:
  ```bash
  python manager_v2.py visualize --id <ENTRY_ID>
  ```

### 3.2 配置文件示例 (config.json)
```json
{
  "app_name": "SeedPlan2026",
  "root_dir": "d:/Seed",
  "mirror_dir": "e:/SeedBackup",
  "secret_key": "YOUR_SECURE_KEY",
  "compression": true,
  "encryption": true
}
```

## 4. 开发说明
- **Sidecar 模式**: 每个对象伴随一个 `.meta` 文件，作为数据的最终事实来源。
- **CAS 存储**: 内容寻址存储，通过哈希值进行分片存储，避免文件名冲突并支持去重。
- **乐观锁**: 在并发写入时通过版本号检测冲突。
