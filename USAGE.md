# EternalCore 指令使用文档 (EternalCore CLI Documentation)

EternalCore 是一个分布式、去中心化的数字资产持久化引擎，支持全网格同步、版本控制、加密压缩及元数据扩展。

## 1. 基础配置 (Basic Configuration)

默认根目录为当前目录下的数据文件夹，可以通过命令行参数覆盖：

- `--root`: 指定主存储根目录 (默认: `d:\Seed`)
- `--config`: 指定 JSON 配置文件路径 (可选)
- `--role`: 初始化时指定节点角色：
    - `master`: 主节点，拥有完整读写权限。
    - `contributor`: 贡献者节点，可读写。
    - `mirror`: 镜像节点，**只读**，仅用于同步全网数据。
- `--federation-id`: 初始化时指定联邦 ID，用于隔离不同的网络环境。
- `--mirror-dir`: 初始化时指定一个本地镜像备份目录（如外部磁盘路径）。

## 2. 核心指令 (Core Commands)

### 2.1 初始化与身份
- **初始化仓库**:
  ```bash
  # 创建一个新的主节点，并设置本地备份目录
  python manager_v2.py init --role master --mirror-dir e:/Backup
  
  # 创建一个镜像节点加入现有网络
  python manager_v2.py init --role mirror --federation-id <FED_ID>
  ```
- **健康检查**: 查看系统运行状态、节点 ID、联邦 ID 及磁盘空间。
  ```bash
  python manager_v2.py health
  ```

### 2.2 数据操作 (Data Operations)
- **添加/更新条目**:
  ```bash
  # 自动触发全网广播同步
  python manager_v2.py put <ID> "内容或文件路径" --type "类型" --meta '{"key":"value"}'
  ```
- **获取条目**:
  ```bash
  python manager_v2.py get <ID>
  ```
- **查看列表**:
  ```bash
  python manager_v2.py list
  ```

### 2.3 分布式同步 (Distributed Sync)
Seed 支持全网格 (Full Mesh) 自动同步，任何本地更改都会自动广播给已知对等节点。

- **添加对等节点 (Peer)**:
  ```bash
  python manager_v2.py peer add <NAME> <PATH_OR_URL>
  ```
- **列出对等节点**:
  ```bash
  python manager_v2.py peer list
  ```
- **手动触发全网广播**:
  ```bash
  python manager_v2.py peer sync
  ```
- **主动同步 (全网格)**:
  ```bash
  # 向所有已注册的节点同步更新（基于兴趣订阅）
  python manager_v2.py peer sync
  ```
- **手动推送/拉取 (指定节点)**:
  ```bash
  # 仅在建立新连接或特殊情况下使用
  python manager_v2.py push <PATH_OR_URL>
  python manager_v2.py pull <PATH_OR_URL>
  ```

### 2.5 选择性同步 (Selective Sync)
除了主节点外，其他节点可以只存储自己感兴趣的数据。这通过“兴趣过滤器”实现：
- **添加订阅**:
  ```bash
  # 只接收 data_type 为 'doc' 的数据
  python manager_v2.py peer subscribe data_type doc
  
  # 只接收元数据中 category 为 'Science' 的数据
  python manager_v2.py peer subscribe metadata.category Science

  # 只同步存储特定目录（如 src/ 目录）
  python manager_v2.py peer subscribe path src/
  ```
- **移除订阅**:
  ```bash
  python manager_v2.py peer subscribe data_type doc --remove
  ```
- **工作原理**:
    1. 当你执行 `sync` 或 `push` 时，系统会先询问对方的兴趣。
    2. 只有符合对方订阅条件的数据才会被传输。
    3. 主节点默认不设过滤器，存储全网全量数据。

## 3. 进阶功能 (Advanced Features)

### 3.1 导入与导出
- **导出数据包 (ZIP)**:
  ```bash
  python manager_v2.py export my_data.zip --type "Science"
  ```
- **导入数据包 (ZIP)**:
  ```bash
  python manager_v2.py import my_data.zip
  ```

### 3.2 依赖与可视化
- **验证依赖链**:
  ```bash
  python manager_v2.py validate <ID>
  ```
- **可视化依赖图**:
  ```bash
  python manager_v2.py visualize <ID>
  ```

### 3.3 系统维护
- **重建索引**:
  ```bash
  python manager_v2.py rebuild
  ```
- **系统审计**: 验证数据完整性及 Merkle 链。
  ```bash
  python manager_v2.py audit
  ```

## 4. 开发者扩展

### 4.1 远程传输接口 (RemoteAdapter)
如果您需要支持自定义的网络同步（如 HTTP, P2P），可以继承 `RemoteAdapter` 类并实现以下方法：
- `get_all_hashes()`
- `push_object(h, obj_bytes, meta_bytes)`
- `pull_object(h)`
- `update_index(objects_data)`

然后将该实例传入 `core.push()` 或 `core.pull()` 即可实现差量同步。
