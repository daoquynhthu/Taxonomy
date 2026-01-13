import os
import sys
import json
import sqlite3
import hashlib
import shutil
import hmac
import tempfile
import logging
import zlib
import base64
import uuid
import typing
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    Fernet = None
    hashes = None
    PBKDF2HMAC = None
    Scrypt = None

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("seed_system.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SeedCore")

class RemoteAdapter:
    """Abstract interface for remote repository operations."""
    def get_federation_id(self): raise NotImplementedError()
    def get_interests(self): raise NotImplementedError() # Returns list of (key, value)
    def get_all_hashes(self): raise NotImplementedError()
    def push_object(self, h, obj_bytes, meta_bytes): raise NotImplementedError()
    def pull_object(self, h): raise NotImplementedError() # Returns (obj_bytes, meta_bytes)
    def get_objects_by_hashes(self, hashes): raise NotImplementedError() # Returns list of dicts
    def update_index(self, objects_data): raise NotImplementedError()
    def authenticate(self, challenge): raise NotImplementedError() # Returns dict with signature and node info

class LocalFileSystemAdapter(RemoteAdapter):
    """Adapter for local file system repositories."""
    def __init__(self, path):
        self.path = Path(path).resolve()
        if self.path.name != ".eternal" and (self.path / ".eternal").exists():
            self.path = self.path / ".eternal"
        self.core = EternalCore(self.path, auto_sync=False)

    def get_federation_id(self):
        return self.core.get_federation_id()

    def get_interests(self):
        return self.core.get_interests()

    def get_all_hashes(self):
        return self.core.get_all_hashes()

    def push_object(self, h, obj_bytes, meta_bytes):
        shard_rel = Path(h[0:2]) / h[2:4] / h
        dest_obj = self.core.objects_dir / shard_rel / h
        dest_meta = dest_obj.with_suffix('.meta')
        dest_obj.parent.mkdir(parents=True, exist_ok=True)
        
        with open(dest_obj, 'wb') as f: f.write(obj_bytes)
        with open(dest_meta, 'wb') as f: f.write(meta_bytes)

    def pull_object(self, h):
        shard_rel = Path(h[0:2]) / h[2:4] / h
        src_obj = self.core.objects_dir / shard_rel / h
        src_meta = src_obj.with_suffix('.meta')
        return src_obj.read_bytes(), src_meta.read_bytes()

    def get_objects_by_hashes(self, hashes):
        conn = sqlite3.connect(self.core.db_path)
        conn.row_factory = sqlite3.Row
        results = []
        for h in hashes:
            rows = conn.execute("SELECT * FROM objects WHERE content_hash = ?", (h,)).fetchall()
            for row in rows:
                obj_dict = dict(row)
                rels = conn.execute("SELECT * FROM relations WHERE from_id = ?", (row['id'],)).fetchall()
                obj_dict['relations'] = [dict(r) for r in rels]
                results.append(obj_dict)
        conn.close()
        return results

    def update_index(self, objects_data):
        conn = sqlite3.connect(self.core.db_path)
        
        # Load trusted public keys from peers table to verify signatures
        trusted_keys = {}
        res = conn.execute("SELECT public_key, name FROM peers").fetchall()
        for pub_key, name in res:
            if pub_key: trusted_keys[pub_key] = name
            
        # Also trust ourselves
        my_pub = self.core.get_public_key()
        if my_pub: trusted_keys[my_pub] = "self"
        
        for row in objects_data:
            # 1. Signature Verification
            h = row['content_hash']
            sig = row['signature']
            
            # If we have a pool of trusted keys, verify the signature
            is_valid = False
            if not sig:
                logger.warning(f"Object {row['id']} has no signature. Skipping.")
                continue
                
            for pub_key in trusted_keys:
                if self.core.verify_signature(h, sig, pub_key):
                    is_valid = True
                    break
            
            if not is_valid and trusted_keys:
                logger.error(f"Object {row['id']} signature verification failed! Not from a trusted peer.")
                continue
            elif not is_valid and not trusted_keys:
                # If no peers yet, we might be the first one or in bootstrap mode
                # For now, allow but log warning. In strict mode, this would be rejected.
                logger.warning(f"No trusted peers found. Accepting object {row['id']} without verification.")

            # 2. Update DB
            conn.execute("INSERT OR REPLACE INTO objects (id, data_type, content_hash, signature, version, created_at, updated_at, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (row['id'], row['data_type'], row['content_hash'], row['signature'], row['version'], row['created_at'], row['updated_at'], row['metadata']))
            
            # Relations
            if 'relations' in row:
                conn.execute("DELETE FROM relations WHERE from_id = ?", (row['id'],))
                for rel in row['relations']:
                    conn.execute("INSERT INTO relations (from_id, to_id, rel_type) VALUES (?, ?, ?)",
                                (rel['from_id'], rel['to_id'], rel['rel_type']))
        conn.commit()
        conn.close()

    def authenticate(self, challenge):
        """Respond to an authentication challenge."""
        signature = self.core._sign_content(challenge)
        return {
            "signature": signature,
            "public_key": self.core.get_public_key(),
            "node_id": self.core.get_node_id(),
            "role": self.core.get_node_role()
        }

class EternalCore:
    def __init__(self, root_dir, mirror_dir=None, secret_key=None, master_key=None, app_name="EternalCore", auto_sync=True):
        self.root_dir = Path(root_dir).resolve()
        self.objects_dir = self.root_dir / "objects"
        # Database is now inside .eternal
        self.db_path = self.root_dir / "eternal.db"
        self.app_name = app_name
        self.auto_sync = auto_sync
        
        # Mirror configuration
        if mirror_dir:
            self.mirror_dir = Path(mirror_dir).resolve()
            if os.name == 'nt' and self.mirror_dir.drive == self.root_dir.drive:
                logger.warning("Mirror is on the same physical drive as source.")
        else:
            self.mirror_dir = None
            
        self.secret_key = secret_key or "humanity-eternal-2026"
        
        # Encryption Key Setup
        self.fernet = None
        if master_key and HAS_CRYPTO:
            # Try to load unique salt from DB
            salt = b'seed-plan-salt-2026' # Default fallback
            try:
                conn = sqlite3.connect(self.db_path)
                res = conn.execute("SELECT value FROM repo_info WHERE key='crypto_salt'").fetchone()
                conn.close()
                if res:
                    salt = base64.b64decode(res[0])
            except:
                pass

            if HAS_CRYPTO and Scrypt is not None:
                # Use Scrypt (stronger than PBKDF2)
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                )
            elif HAS_CRYPTO and PBKDF2HMAC is not None and hashes is not None:
                # Fallback to PBKDF2
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
            else:
                raise Exception("Cryptography components missing.")
            
            key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
            if Fernet is not None:
                self.fernet = Fernet(key)
            else:
                raise Exception("Fernet missing.")
        elif master_key and not HAS_CRYPTO:
            logger.error("Master key provided but 'cryptography' library is not installed!")
            
        self._init_db()
        logger.info(f"SeedCore initialized at {self.root_dir}")

    def _encrypt(self, data):
        """Encrypt data using Fernet (AES-128 in CBC mode with HMAC)."""
        if not self.fernet:
            raise Exception("Encryption error: No master key provided or cryptography library missing.")
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.fernet.encrypt(data)

    def _decrypt(self, encrypted_data):
        """Decrypt data."""
        if not self.fernet:
            raise Exception("Decryption error: No master key provided or cryptography library missing.")
        return self.fernet.decrypt(encrypted_data)

    def _calculate_hash(self, data):
        """Stream-friendly hash calculation."""
        sha256 = hashlib.sha256()
        if isinstance(data, (bytes, bytearray)):
            sha256.update(data)
        elif isinstance(data, str):
            sha256.update(data.encode('utf-8'))
        elif hasattr(data, 'read'): # Handle file-like objects
            for chunk in iter(lambda: data.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @classmethod
    def from_config(cls, config_path):
        """Create an EternalCore instance from a JSON config file."""
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            
        # Handle secret keys from separate files if provided
        secret_key = config.get('secret_key')
        if config.get('secret_key_file'):
            with open(config['secret_key_file'], 'r') as sf:
                secret_key = sf.read().strip()
                
        master_key = config.get('master_key')
        if config.get('master_key_file'):
            with open(config['master_key_file'], 'r') as mf:
                master_key = mf.read().strip()
                
        return cls(
            root_dir=config['root_dir'],
            mirror_dir=config.get('mirror_dir'),
            secret_key=secret_key,
            master_key=master_key,
            app_name=config.get('app_name', 'EternalCore')
        )

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        
        # Generic objects table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS objects (
                id TEXT PRIMARY KEY,
                data_type TEXT,
                content_hash TEXT,
                signature TEXT,
                version INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                metadata TEXT
            )
        ''')
        
        # Peer nodes for distributed sync
        conn.execute('''
            CREATE TABLE IF NOT EXISTS peers (
                name TEXT PRIMARY KEY,
                url TEXT,
                last_seen TEXT,
                trust_level INTEGER DEFAULT 1,
                role TEXT DEFAULT 'mirror', -- master, contributor, mirror
                public_key TEXT
            )
        ''')
        
        # ... (rest of the tables remain the same)
        
        # Generic relationships table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS relations (
                from_id TEXT,
                to_id TEXT,
                rel_type TEXT,
                PRIMARY KEY (from_id, to_id, rel_type)
            )
        ''')
        
        # History for versioning
        conn.execute('''
            CREATE TABLE IF NOT EXISTS history (
                obj_id TEXT,
                version INTEGER,
                content_hash TEXT,
                timestamp TEXT,
                metadata TEXT,
                PRIMARY KEY (obj_id, version)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS state_chain (
                height INTEGER PRIMARY KEY AUTOINCREMENT,
                state_hash TEXT,
                merkle_root TEXT,
                prev_state_hash TEXT,
                timestamp TEXT
            )
        ''')
        
        # Merkle Tree nodes cache for incremental updates
        conn.execute('''
            CREATE TABLE IF NOT EXISTS merkle_cache (
                level INTEGER,
                pos INTEGER,
                hash TEXT,
                PRIMARY KEY (level, pos)
            )
        ''')
        
        # Repo info table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS repo_info (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # Subscriptions for selective sync (Interests)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                filter_key TEXT,    -- e.g., 'data_type', 'metadata.category'
                filter_value TEXT,  -- e.g., 'doc', 'Science'
                PRIMARY KEY (filter_key, filter_value)
            )
        ''')
        
        # Composite indexes for performance
        conn.execute('CREATE INDEX IF NOT EXISTS idx_obj_type ON objects(data_type)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_hash_version ON history(content_hash, version)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_obj_history ON history(obj_id, version)')
        
        conn.commit()
        conn.close()
        
    @staticmethod
    def find_repo_root(start_path="."):
        """Find the root of the EternalCore repository by looking for .eternal directory."""
        curr = Path(start_path).resolve()
        while curr != curr.parent:
            if (curr / ".eternal").is_dir():
                return curr
            curr = curr.parent
        return None

    @classmethod
    def init_repo(cls, path=".", app_name="EternalCore", role="master", federation_id=None, mirror_dir=None):
        """Initialize a new repository at the given path."""
        root = Path(path).resolve()
        eternal_dir = root / ".eternal"
        if eternal_dir.exists():
            print(f"Error: Repository already exists at {root}")
            return None
            
        eternal_dir.mkdir(parents=True)
        (eternal_dir / "objects").mkdir()
        (eternal_dir / "metadata").mkdir()
        
        # Create a default config
        config = {
            "root_dir": str(eternal_dir),
            "app_name": app_name,
            "mirror_dir": str(Path(mirror_dir).resolve()) if mirror_dir else None,
            "created_at": datetime.now().isoformat()
        }
        with open(eternal_dir / "config.json", 'w') as f:
            json.dump(config, f, indent=2)
            
        core = cls(eternal_dir, app_name=app_name, mirror_dir=config["mirror_dir"])
        
        # Record init info
        conn = sqlite3.connect(core.db_path)
        
        # Generate Identity Keypair (ED25519)
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode()

        # Generate Node ID and Federation ID
        node_id = str(uuid.uuid4())
        if not federation_id:
            federation_id = str(uuid.uuid4())
            print(f"Created new federation: {federation_id}")
        else:
            print(f"Joining existing federation: {federation_id}")

        # Generate a unique salt for this repository
        crypto_salt = base64.b64encode(os.urandom(16)).decode()

        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("init_date", datetime.now().isoformat()))
        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("version", "3.0"))
        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("private_key", priv_bytes))
        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("public_key", pub_bytes))
        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("role", role))
        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("node_id", node_id))
        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("federation_id", federation_id))
        conn.execute("INSERT INTO repo_info (key, value) VALUES (?, ?)", ("crypto_salt", crypto_salt))
        conn.commit()
        conn.close()
        
        print(f"Initialized empty EternalCore repository in {eternal_dir}")
        print(f"Node ID: {node_id}")
        print(f"Role: {role}")
        return core

    def put_safe(self, obj_id, content, metadata=None, data_type="blob", relations=None, max_retries=3):
        """Wrapper for put with automatic retry on concurrency conflicts."""
        import time
        import random
        
        for attempt in range(max_retries):
            try:
                return self.put(obj_id, content, metadata, data_type, relations)
            except Exception as e:
                if "Concurrency conflict" in str(e) and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 0.1 + random.uniform(0, 0.1)
                    logger.warning(f"Concurrency conflict for {obj_id}. Retrying in {wait_time:.2f}s... (Attempt {attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                else:
                    raise

    def calculate_merkle_root(self):
        """Calculate the Merkle Root for all objects."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. Get current leaf hashes (ordered by ID for determinism)
        cursor.execute("SELECT content_hash FROM objects ORDER BY id")
        leaves = [row[0] for row in cursor.fetchall()]
        
        if not leaves:
            conn.close()
            return "0" * 64
            
        # 2. Build tree and cache levels
        # Note: A truly incremental tree would only update the branch of the changed leaf.
        # Here we optimize by using the cache to avoid re-calculating unchanged branches 
        # if the number of leaves remains the same.
        current_level = leaves
        level = 0
        
        # Simple optimization: If number of leaves hasn't changed, we could theoretically 
        # compare with cache. For now, we rebuild but store in cache for future 
        # partial update implementation.
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i]
                if i + 1 < len(current_level):
                    combined += current_level[i+1]
                else:
                    # Odd number of nodes: hash with itself or just pass through
                    combined += current_level[i] 
                
                next_level.append(self._calculate_hash(combined))
            
            current_level = next_level
            level += 1
            
        root = current_level[0]
        
        # Update cache with the new root
        cursor.execute("INSERT OR REPLACE INTO merkle_cache (level, pos, hash) VALUES (?, 0, ?)", (level, root))
        
        conn.commit()
        conn.close()
        return root

    def commit_state(self):
        """Commit current state to the 'blockchain' state chain."""
        merkle_root = self.calculate_merkle_root()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get previous state hash
        cursor.execute("SELECT state_hash FROM state_chain ORDER BY height DESC LIMIT 1")
        row = cursor.fetchone()
        prev_hash = row[0] if row else "0" * 64
        
        # New state hash = hash(prev_hash + merkle_root)
        new_state_hash = self._calculate_hash(prev_hash + merkle_root)
        
        cursor.execute('''
            INSERT INTO state_chain (state_hash, merkle_root, prev_state_hash, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (new_state_hash, merkle_root, prev_hash, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        print(f"State Committed. Height: {new_state_hash[:8]} | Merkle: {merkle_root[:8]}")
        return new_state_hash

    def _sign_content(self, content_hash):
        """Sign content hash using node's private key (ED25519)."""
        conn = sqlite3.connect(self.db_path)
        res = conn.execute("SELECT value FROM repo_info WHERE key='private_key'").fetchone()
        conn.close()
        
        if not res:
            # Fallback to HMAC if identity not yet established
            return hmac.new(b"eternal-secret", content_hash.encode(), hashlib.sha256).hexdigest()
            
        priv_key_str = res[0]
        # Satisfy linter by explicitly handling ED25519
        private_key = serialization.load_pem_private_key(priv_key_str.encode(), password=None)
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            signature_bytes = private_key.sign(content_hash.encode())
            return base64.b64encode(signature_bytes).decode()
        else:
            # For other key types, they might require padding/algorithm, but we only use ED25519
            raise ValueError(f"Unsupported key type: {type(private_key)}")

    def verify_signature(self, content_hash, signature, public_key_str):
        """Verify if a signature is valid for a given hash and public key."""
        try:
            public_key = serialization.load_ssh_public_key(public_key_str.encode())
            sig_bytes = base64.b64decode(signature)
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(sig_bytes, content_hash.encode())
                return True
            else:
                # We only support ED25519 for now
                return False
        except Exception:
            return False



    def _atomic_write(self, path, data):
        """Atomic write using a temporary file."""
        temp_path = path.with_suffix('.tmp')
        if isinstance(data, (bytes, bytearray)):
            with open(temp_path, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        else:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        os.replace(temp_path, path)

    def get_object_content(self, content_hash):
        """Retrieve, decrypt, and decompress an object based on its sidecar metadata."""
        shard_dir = self.objects_dir / content_hash[0:2] / content_hash[2:4]
        obj_path = shard_dir / content_hash
        meta_path = shard_dir / f"{content_hash}.meta"
        
        if not obj_path.exists():
            raise FileNotFoundError(f"Object {content_hash} not found in storage.")
            
        with open(obj_path, 'rb') as f:
            content = f.read()
            
        # Try to read sidecar metadata for this specific object
        if meta_path.exists():
            with open(meta_path, 'rb') as f:
                meta_raw = f.read()
            
            # Check for encrypted metadata header
            if meta_raw.startswith(b"[ENCRYPTED]"):
                if not self.fernet:
                    raise Exception("Metadata is encrypted but no master key provided.")
                meta_json = self.fernet.decrypt(meta_raw[11:]).decode('utf-8')
                meta = json.loads(meta_json)
            else:
                meta = json.loads(meta_raw.decode('utf-8'))
            
            if meta.get('encryption'):
                content = self._decrypt(content)
                
            if meta.get('compression') == 'zlib':
                content = zlib.decompress(content)
        
        return content

    def _store_object(self, content, metadata=None, compress=True, encrypt=False):
        """Store content with optional compression and encryption."""
        if isinstance(content, str):
            content = content.encode('utf-8')

        if compress:
            content = zlib.compress(content, level=9)
            if metadata:
                metadata['compression'] = 'zlib'
        
        if encrypt:
            content = self._encrypt(content)
            if metadata:
                metadata['encryption'] = 'fernet-aes128'

        h = self._calculate_hash(content)
        shard_dir = self.objects_dir / h[0:2] / h[2:4]
        shard_dir.mkdir(parents=True, exist_ok=True)
        
        obj_path = shard_dir / h
        if not obj_path.exists():
            self._atomic_write(obj_path, content)
            
            # Store sidecar metadata for the object itself (not the entry)
            if metadata:
                meta_path = shard_dir / f"{h}.meta"
                meta_json = json.dumps(metadata, indent=2, ensure_ascii=False)
                if encrypt and self.fernet:
                    # Encrypt metadata as well if encryption is enabled
                    encrypted_meta = b"[ENCRYPTED]" + self.fernet.encrypt(meta_json.encode('utf-8'))
                    self._atomic_write(meta_path, encrypted_meta)
                else:
                    self._atomic_write(meta_path, meta_json)
                
            # Mirroring
            if self.mirror_dir:
                try:
                    mirror_shard = self.mirror_dir / h[0:2] / h[2:4]
                    mirror_shard.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(obj_path, mirror_shard / h)
                    if metadata:
                        shutil.copy2(shard_dir / f"{h}.meta", mirror_shard / f"{h}.meta")
                except Exception as e:
                    logger.error(f"Mirroring failed for {h}: {e}")
                    
        return h


    def put(self, obj_id, content, metadata=None, data_type="blob", relations=None):
        """Store an arbitrary object with metadata and version control."""
        # Role check: Mirror nodes are read-only for users
        if self.get_node_role() == "mirror":
            raise PermissionError("Mirror nodes are read-only. Data must be synchronized from other peers.")

        metadata = metadata or {}
        relations = relations or [] # List of (to_id, rel_type)
        
        compress = metadata.get('compress', True)
        encrypt = metadata.get('encrypt', False)
        
        # 1. Store physical object
        obj_meta = {
            "id": obj_id,
            "data_type": data_type,
            "timestamp": datetime.now().isoformat(),
            "encryption": encrypt,
            "compression": "zlib" if compress else None,
            "user_metadata": metadata
        }
        
        content_hash = self._store_object(content, metadata=obj_meta, compress=compress, encrypt=encrypt)
        signature = self._sign_content(content_hash)
        
        # 2. Database update with Optimistic Locking
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT version FROM objects WHERE id = ?", (obj_id,))
            row = cursor.fetchone()
            old_version = row[0] if row else 0
            new_version = old_version + 1
            now_str = datetime.now().isoformat()
            
            # Store Sidecar Meta (Source of Truth)
            sidecar_payload = {
                "id": obj_id,
                "data_type": data_type,
                "content_hash": content_hash,
                "signature": signature,
                "version": new_version,
                "relations": relations,
                "metadata": metadata,
                "compression": "zlib" if compress else None,
                "encryption": encrypt,
                "created_at": now_str
            }
            
            shard_dir = self.objects_dir / content_hash[0:2] / content_hash[2:4]
            meta_path = shard_dir / f"{content_hash}.meta"
            self._atomic_write(meta_path, json.dumps(sidecar_payload, indent=2, ensure_ascii=False))
            
            # Update Index
            if old_version == 0:
                cursor.execute('''
                    INSERT INTO objects (id, data_type, content_hash, signature, version, created_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (obj_id, data_type, content_hash, signature, new_version, now_str, json.dumps(metadata)))
            else:
                cursor.execute('''
                    UPDATE objects 
                    SET data_type=?, content_hash=?, signature=?, version=?, updated_at=?, metadata=?
                    WHERE id=? AND version=?
                ''', (data_type, content_hash, signature, new_version, now_str, json.dumps(metadata), obj_id, old_version))
                
                if cursor.rowcount == 0:
                    raise Exception(f"Concurrency conflict: Object {obj_id} was updated by another process.")

            # Record History
            cursor.execute('''
                INSERT INTO history (obj_id, version, content_hash, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (obj_id, new_version, content_hash, now_str, json.dumps(sidecar_payload)))
            
            # Update Relations
            cursor.execute("DELETE FROM relations WHERE from_id = ?", (obj_id,))
            for to_id, rel_type in relations:
                cursor.execute("INSERT INTO relations (from_id, to_id, rel_type) VALUES (?, ?, ?)", (obj_id, to_id, rel_type))
            
            conn.commit()
            logger.info(f"Stored object [{obj_id}] v{new_version}")
            
            # Automatic Sync & Broadcast
            if self.auto_sync:
                if self.mirror_dir:
                    try:
                        self.sync_to_mirror()
                    except Exception as e:
                        logger.error(f"Auto-sync to mirror failed: {e}")
                
                # Broadcast to network
                try:
                    self.broadcast()
                except Exception as e:
                    logger.error(f"Network broadcast failed: {e}")
            
            return content_hash
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to put object {obj_id}: {e}")
            raise
        finally:
            conn.close()

    def get(self, obj_id):
        """Retrieve object content and metadata."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM objects WHERE id = ?", (obj_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        content = self.get_object_content(row['content_hash'])
        return {
            "content": content,
            "metadata": json.loads(row['metadata']),
            "data_type": row['data_type'],
            "version": row['version']
        }

    def rollback(self, obj_id, target_version):
        """Roll back an object to a specific version from history."""
        logger.info(f"Initiating rollback for {obj_id} to version {target_version}")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            # 1. Find the version in history
            cursor.execute("SELECT * FROM history WHERE obj_id = ? AND version = ?", (obj_id, target_version))
            hist_row = cursor.fetchone()
            if not hist_row:
                logger.error(f"Version {target_version} not found for object {obj_id}")
                return False
            
            sidecar_payload = json.loads(hist_row['metadata'])
            content_hash = hist_row['content_hash']
            
            # 2. Perform the rollback update
            cursor.execute("SELECT version FROM objects WHERE id = ?", (obj_id,))
            current_version = cursor.fetchone()[0]
            new_version = current_version + 1
            now_str = datetime.now().isoformat()
            
            cursor.execute('''
                UPDATE objects SET 
                data_type=?, content_hash=?, signature=?, version=?, updated_at=?, metadata=?
                WHERE id=?
            ''', (sidecar_payload['data_type'], content_hash, sidecar_payload['signature'], new_version, now_str, json.dumps(sidecar_payload['metadata']), obj_id))
            
            # 3. Record the rollback event in history
            cursor.execute('''
                INSERT INTO history (obj_id, content_hash, version, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (obj_id, content_hash, new_version, now_str, json.dumps(sidecar_payload)))
            
            # 4. Restore relations
            cursor.execute("DELETE FROM relations WHERE from_id = ?", (obj_id,))
            for to_id, rel_type in sidecar_payload.get('relations', []):
                cursor.execute("INSERT INTO relations (from_id, to_id, rel_type) VALUES (?, ?, ?)", (obj_id, to_id, rel_type))
            
            conn.commit()
            self.commit_state()
            logger.info(f"Rollback successful: {obj_id} v{new_version} (restored from v{target_version})")
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Rollback failed: {e}")
            return False
        finally:
            conn.close()

    def validate_relations(self, obj_id, visited=None):
        """Recursively ensure relations are valid and targets exist."""
        if visited is None:
            visited = set()
        
        if obj_id in visited:
            return True, []
        
        visited.add(obj_id)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM objects WHERE id = ?", (obj_id,))
        if not cursor.fetchone():
            conn.close()
            return False, [obj_id]
        
        cursor.execute("SELECT to_id FROM relations WHERE from_id = ?", (obj_id,))
        targets = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        missing_all = []
        for target_id in targets:
            ok, missing = self.validate_relations(target_id, visited)
            if not ok:
                missing_all.extend(missing)
        
        return len(missing_all) == 0, list(set(missing_all))

    def visualize_relations(self, obj_id, level=0, visited=None):
        """Generate a text-based relation graph visualization."""
        if visited is None:
            visited = set()
            
        obj = self.get(obj_id)
        if not obj:
            print("  " * level + f"[-] {obj_id} (MISSING)")
            return
            
        prefix = "└── " if level > 0 else "ROOT: "
        print("  " * level + f"{prefix}{obj_id} [{obj['data_type']}]")
        
        if obj_id in visited:
            print("  " * (level + 1) + "└── (ALREADY VISITED)")
            return
            
        visited.add(obj_id)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT to_id, rel_type FROM relations WHERE from_id = ?", (obj_id,))
        relations = cursor.fetchall()
        conn.close()
        
        for to_id, rel_type in relations:
            print("  " * (level + 1) + f"({rel_type})")
            self.visualize_relations(to_id, level + 1, visited)

    def health_check(self):
        """Perform a comprehensive system health check."""
        checks = {
            "node": {
                "id": self.get_node_id(),
                "role": self.get_node_role(),
                "federation_id": self.get_federation_id()
            },
            "database": self._check_db_connection(),
            "primary_storage": self._check_storage(self.objects_dir),
            "mirror_storage": self._check_storage(self.mirror_dir) if self.mirror_dir else {"accessible": False, "status": "Not configured"},
            "state_chain": self.verify_state_chain(),
            "last_commit": self._get_last_commit_time()
        }
        return checks

    def _check_db_connection(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("SELECT 1")
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    def _check_storage(self, path):
        """Check storage availability and space."""
        if not path or not path.exists():
            return {"accessible": False, "status": "Missing or inaccessible"}
        
        try:
            stat = shutil.disk_usage(path)
            free_percent = (stat.free / stat.total) * 100
            
            return {
                "accessible": True,
                "free_space_gb": round(stat.free / (1024**3), 2),
                "free_percent": round(free_percent, 2),
                "warning": free_percent < 10
            }
        except Exception as e:
            logger.error(f"Storage check failed for {path}: {e}")
            return {"accessible": False, "status": "Error during check"}

    def _get_last_commit_time(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp FROM state_chain ORDER BY height DESC LIMIT 1")
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else None
        except:
            return None

    def audit_all(self):
        """Verify integrity of all objects in the database."""
        print("Starting full system audit...")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM objects")
        rows = cursor.fetchall()
        
        issues = []
        for row in rows:
            obj_id = row['id']
            h = row['content_hash']
            sig = row['signature']
            
            # 1. Physical file check
            shard_dir = self.objects_dir / h[0:2] / h[2:4]
            obj_path = shard_dir / h
            if not obj_path.exists():
                issues.append(f"MISSING_FILE: Object {obj_id} (hash {h})")
                continue
                
            # 2. Hash integrity check
            actual_h = self._calculate_hash(open(obj_path, 'rb').read())
            if actual_h != h:
                issues.append(f"HASH_MISMATCH: Object {obj_id} (expected {h}, got {actual_h})")
                
            # 3. Signature check
            if row['signature'] != self._sign_content(h):
                issues.append(f"INVALID_SIGNATURE: Object {obj_id}")
                
        conn.close()
        
        # Merkle State Audit
        current_root = self.calculate_merkle_root()
        print(f"Current Global State Root: {current_root}")
        
        if not issues:
            print("Audit completed: No issues found.")
            return True
        else:
            print(f"Audit completed: Found {len(issues)} issues.")
            for issue in issues:
                print(f"  - {issue}")
            return False

    def rebuild_index(self):
        """Rebuild the SQLite index from all .meta files in the objects directory."""
        print("Rebuilding index from physical sidecar files...")
        conn = sqlite3.connect(self.db_path)
        # Ensure schema is up to date before rebuild
        conn.execute('DROP TABLE IF EXISTS objects')
        conn.execute('DROP TABLE IF EXISTS relations')
        conn.execute('DROP TABLE IF EXISTS history')
        conn.close()
        self._init_db()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for meta_file in self.objects_dir.glob("**/*.meta"):
            with open(meta_file, 'r', encoding='utf-8') as f:
                m = json.load(f)
                if 'id' not in m: continue # Skip object-level meta without ID
                
                obj_id = m['id']
                ver = m.get('version', 1)
                data_type = m.get('data_type', 'blob')
                content_hash = m.get('content_hash')
                signature = m.get('signature')
                metadata = m.get('metadata', {})
                created_at = m.get('created_at', datetime.now().isoformat())
                
                cursor.execute('''
                    INSERT OR REPLACE INTO objects 
                    (id, data_type, content_hash, signature, version, created_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (obj_id, data_type, content_hash, signature, ver, created_at, json.dumps(metadata)))
                
                cursor.execute('''
                    INSERT OR IGNORE INTO history (obj_id, version, content_hash, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?)
                ''', (obj_id, ver, content_hash, created_at, json.dumps(m)))

                for to_id, rel_type in m.get('relations', []):
                    cursor.execute('INSERT OR REPLACE INTO relations (from_id, to_id, rel_type) VALUES (?, ?, ?)', (obj_id, to_id, rel_type))
        
        conn.commit()
        conn.close()
        print("Index rebuilt successfully.")

    def search(self, query=None, data_type=None):
        """Search for objects by metadata or data_type."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        sql = "SELECT id, data_type, content_hash, version, created_at FROM objects WHERE 1=1"
        params = []
        
        if query:
            sql += " AND (id LIKE ? OR metadata LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])
        
        if data_type:
            sql += " AND data_type = ?"
            params.append(data_type)
            
        cursor.execute(sql, params)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def verify_state_chain(self, verbose=False):
        """Verify the integrity of the entire state chain (Blockchain validation)."""
        if verbose:
            print("Verifying state chain integrity...")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT height, state_hash, merkle_root, prev_state_hash FROM state_chain ORDER BY height ASC")
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            if verbose:
                print("State chain is empty.")
            return True
            
        expected_prev_hash = "0" * 64
        for height, state_hash, merkle_root, prev_state_hash in rows:
            # 1. Check Linkage
            if prev_state_hash != expected_prev_hash:
                print(f"CHAIN BROKEN at height {height}: prev_hash mismatch!")
                return False
            
            # 2. Check State Hash derivation
            actual_state_hash = self._calculate_hash(prev_state_hash + merkle_root)
            if actual_state_hash != state_hash:
                print(f"INVALID STATE at height {height}: state_hash mismatch!")
                return False
            
            expected_prev_hash = state_hash
            
        # 3. Verify current Merkle Root matches the latest block
        current_merkle = self.calculate_merkle_root()
        if rows and rows[-1][2] != current_merkle:
            print("CRITICAL: Current data does not match the latest state root!")
            return False
            
        print(f"State Chain Verified. Height: {len(rows)}, Current Root: {current_merkle[:8]}")
        return True

    def broadcast(self):
        """Broadcast local changes to all known peers in the network."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        peers = conn.execute("SELECT name, url FROM peers").fetchall()
        conn.close()
        
        if not peers:
            return
            
        print(f"Broadcasting to {len(peers)} peers...")
        for peer in peers:
            try:
                print(f"  -> Syncing with peer '{peer['name']}' ({peer['url']})...")
                self.push(peer['url'])
            except Exception as e:
                logger.error(f"Failed to sync with peer {peer['name']}: {e}")

    def add_peer(self, name, url):
        """Register a new neighbor node after verifying federation ID and identity."""
        import secrets
        remote_path = Path(url).resolve()
        if remote_path.name != ".eternal" and (remote_path / ".eternal").exists():
            remote_path = remote_path / ".eternal"
            
        try:
            adapter = LocalFileSystemAdapter(remote_path.parent)
            
            # 1. Federation Check
            local_fed = self.get_federation_id()
            remote_fed = adapter.get_federation_id()
            
            if local_fed and remote_fed and local_fed != remote_fed:
                print(f"Error: Cannot add peer. Federation mismatch!")
                return False
                
            # 2. Challenge-Response Authentication
            challenge = secrets.token_hex(32)
            auth_data = adapter.authenticate(challenge)
            
            signature = auth_data.get("signature")
            public_key = auth_data.get("public_key")
            node_id = auth_data.get("node_id")
            role = auth_data.get("role")
            
            if not self.verify_signature(challenge, signature, public_key):
                print(f"Error: Peer authentication failed! Signature invalid.")
                return False
                
            # 3. Store Peer with Identity Info
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT OR REPLACE INTO peers (name, url, last_seen, public_key, role) 
                VALUES (?, ?, datetime('now'), ?, ?)
            """, (name, str(remote_path.parent), public_key, role))
            conn.commit()
            conn.close()
            
            print(f"Peer '{name}' verified and added (Node ID: {(node_id or 'unknown')[:8]}, Role: {role})")
            return True
        except Exception as e:
            print(f"Error: Could not verify remote node at {url}: {e}")
            return False

    def get_federation_id(self):
        """Get the federation ID for this repository."""
        conn = sqlite3.connect(self.db_path)
        res = conn.execute("SELECT value FROM repo_info WHERE key='federation_id'").fetchone()
        conn.close()
        return res[0] if res else None

    def get_public_key(self):
        """Get the public key of this node."""
        conn = sqlite3.connect(self.db_path)
        res = conn.execute("SELECT value FROM repo_info WHERE key='public_key'").fetchone()
        conn.close()
        return res[0] if res else None

    def get_node_id(self):
        """Get the unique node ID for this repository."""
        conn = sqlite3.connect(self.db_path)
        res = conn.execute("SELECT value FROM repo_info WHERE key='node_id'").fetchone()
        conn.close()
        return res[0] if res else None

    def get_node_role(self):
        """Get the role of this node."""
        conn = sqlite3.connect(self.db_path)
        res = conn.execute("SELECT value FROM repo_info WHERE key='role'").fetchone()
        conn.close()
        return res[0] if res else "mirror"

    def get_all_hashes(self):
        """Get a set of all content hashes in the repository for differential sync."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT content_hash FROM objects")
        hashes = {row[0] for row in cursor.fetchall()}
        conn.close()
        return hashes

    def get_interests(self):
        """Get the subscription filters for this repository."""
        conn = sqlite3.connect(self.db_path)
        res = conn.execute("SELECT filter_key, filter_value FROM subscriptions").fetchall()
        conn.close()
        return [(r[0], r[1]) for r in res]

    def matches_filters(self, obj_data, filters):
        """Check if an object matches the given filters (Interests)."""
        if not filters:
            return True # No filters means interested in everything
            
        for key, val in filters:
            if key == "data_type":
                if obj_data.get("data_type") == val: return True
            elif key == "path":
                obj_id = obj_data.get("id", "")
                # Support prefix matching for directories (e.g., 'src/' matches 'src/main.py')
                if obj_id.startswith(val): return True
            elif key.startswith("metadata."):
                meta_key = key.split(".", 1)[1]
                metadata = obj_data.get("metadata", {})
                if isinstance(metadata, str):
                    try: metadata = json.loads(metadata)
                    except: metadata = {}
                if metadata.get(meta_key) == val: return True
        return False

    def push(self, remote):
        """
        Intelligent Delta Push using RemoteAdapter.
        'remote' can be a URL string (local path) or a RemoteAdapter instance.
        """
        if isinstance(remote, (str, Path)):
            remote = LocalFileSystemAdapter(remote)
            
        print(f"Pushing to remote...")
        
        # 1. Identity & Federation Check
        local_fed = self.get_federation_id()
        remote_fed = remote.get_federation_id()
        if local_fed and remote_fed and local_fed != remote_fed:
            print(f"CRITICAL: Federation mismatch! Local: {local_fed}, Remote: {remote_fed}")
            return False
            
        import secrets
        challenge = secrets.token_hex(32)
        try:
            auth_data = remote.authenticate(challenge)
            if not self.verify_signature(challenge, auth_data.get("signature"), auth_data.get("public_key")):
                print("CRITICAL: Remote identity verification failed!")
                return False
        except Exception as e:
            print(f"Warning: Could not authenticate remote: {e}. Proceeding with caution.")
            
        # 2. Get remote interests for selective sync
        remote_interests = remote.get_interests()
        if remote_interests:
            print(f"Remote has selective interests: {remote_interests}")
            
        local_hashes = self.get_all_hashes()
        remote_hashes = remote.get_all_hashes()
        
        missing_on_remote = local_hashes - remote_hashes
        
        if not missing_on_remote:
            print("Everything up-to-date.")
            return True
            
        # 1. Transfer objects (with filtering)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        
        objects_to_update = []
        pushed_count = 0
        for h in missing_on_remote:
            # Check if remote is interested in any object sharing this hash
            rows = conn.execute("SELECT * FROM objects WHERE content_hash = ?", (h,)).fetchall()
            
            is_interested = False
            for row in rows:
                if self.matches_filters(dict(row), remote_interests):
                    is_interested = True
                    break
            
            if not is_interested:
                continue
                
            shard_rel = Path(h[0:2]) / h[2:4] / h
            src_obj = self.objects_dir / shard_rel / h
            src_meta = src_obj.with_suffix('.meta')
            
            # Use adapter to push bytes
            remote.push_object(h, src_obj.read_bytes(), src_meta.read_bytes())
            pushed_count += 1
            
            # Collect DB records for this hash
            for row in rows:
                obj_dict = dict(row)
                # Also include relations
                rels = conn.execute("SELECT * FROM relations WHERE from_id = ?", (row['id'],)).fetchall()
                obj_dict['relations'] = [dict(r) for r in rels]
                objects_to_update.append(obj_dict)
        
        # 2. Remote Index Update
        if objects_to_update:
            remote.update_index(objects_to_update)
            
        conn.close()
        print(f"Push successful. {pushed_count} objects synchronized.")
        return True

    def pull(self, remote):
        """
        Intelligent Delta Pull using RemoteAdapter.
        'remote' can be a URL string (local path) or a RemoteAdapter instance.
        """
        if isinstance(remote, (str, Path)):
            remote = LocalFileSystemAdapter(remote)
            
        print(f"Pulling from remote...")
        
        # 1. Identity & Federation Check
        local_fed = self.get_federation_id()
        remote_fed = remote.get_federation_id()
        if local_fed and remote_fed and local_fed != remote_fed:
            print(f"CRITICAL: Federation mismatch! Local: {local_fed}, Remote: {remote_fed}")
            return False
            
        import secrets
        challenge = secrets.token_hex(32)
        remote_pub_key = None
        try:
            auth_data = remote.authenticate(challenge)
            remote_pub_key = auth_data.get("public_key")
            if not self.verify_signature(challenge, auth_data.get("signature"), remote_pub_key):
                print("CRITICAL: Remote identity verification failed!")
                return False
        except Exception as e:
            print(f"Warning: Could not authenticate remote: {e}. Proceeding with caution.")
            
        # 2. Get local interests for selective sync
        local_interests = self.get_interests()
        if local_interests:
            print(f"Local has selective interests: {local_interests}")
            
        local_hashes = self.get_all_hashes()
        remote_hashes = remote.get_all_hashes()
        
        missing_locally = remote_hashes - local_hashes
        
        if not missing_locally:
            print("Local repository is up-to-date.")
            return True
            
        # 1. Transfer objects (with filtering)
        # We need to check metadata before pulling the object bytes
        remote_objects_data = remote.get_objects_by_hashes(missing_locally)
        
        pulled_count = 0
        filtered_objects_data = []
        for obj in remote_objects_data:
            if self.matches_filters(obj, local_interests):
                h = obj['content_hash']
                shard_rel = Path(h[0:2]) / h[2:4] / h
                dest_obj = self.objects_dir / shard_rel / h
                dest_meta = dest_obj.with_suffix('.meta')
                dest_obj.parent.mkdir(parents=True, exist_ok=True)
                
                # Use adapter to pull bytes
                obj_bytes, meta_bytes = remote.pull_object(h)
                
                with open(dest_obj, 'wb') as f: f.write(obj_bytes)
                with open(dest_meta, 'wb') as f: f.write(meta_bytes)
                
                filtered_objects_data.append(obj)
                pulled_count += 1
            
        # 2. Local Index Update
        if filtered_objects_data:
            # We reuse LocalFileSystemAdapter's logic to update our own DB
            local_adapter = LocalFileSystemAdapter(self.root_dir)
            local_adapter.update_index(filtered_objects_data)
        
        print(f"Pull successful. {pulled_count} objects synchronized.")
        # Commit local state after pull
        self.commit_state()
        return True

    def sync_to_mirror(self):
        """Manually synchronize all objects and metadata to the mirror directory."""
        if not self.mirror_dir:
            return False
            
        self.mirror_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Sync objects and metadata
        sync_count = 0
        for obj_path in self.objects_dir.rglob("*"):
            if obj_path.is_file():
                rel_path = obj_path.relative_to(self.objects_dir)
                dest_path = self.mirror_dir / "objects" / rel_path
                if not dest_path.exists() or dest_path.stat().st_mtime < obj_path.stat().st_mtime:
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(obj_path, dest_path)
                    sync_count += 1
        
        # 2. Sync database
        db_dest = self.mirror_dir / "eternal.db"
        try:
            shutil.copy2(self.db_path, db_dest)
        except Exception as e:
            logger.warning(f"Database sync warning: {e}")

        return True

    def export_package(self, output_path, data_type=None):
        """Export objects to a ZIP package for transmission."""
        import zipfile
        output_path = Path(output_path)
        print(f"Exporting to {output_path}...")
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT id, content_hash FROM objects"
            params = []
            if data_type:
                query += " WHERE data_type = ?"
                params.append(data_type)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            exported_hashes = set()
            
            for row in rows:
                h = row['content_hash']
                if h in exported_hashes: continue
                
                shard_dir = self.objects_dir / h[0:2] / h[2:4] / h
                # Add content
                content_file = shard_dir / h
                if content_file.exists():
                    zf.write(content_file, arcname=f"objects/{h[0:2]}/{h[2:4]}/{h}/{h}")
                
                # Add meta
                meta_file = shard_dir / f"{h}.meta"
                if meta_file.exists():
                    zf.write(meta_file, arcname=f"objects/{h[0:2]}/{h[2:4]}/{h}/{h}.meta")
                
                exported_hashes.add(h)
            
            # Export DB records (manifest)
            manifest = {
                "version": "3.0",
                "exported_at": datetime.now().isoformat(),
                "objects": [],
                "relations": []
            }
            
            for row in rows:
                # Get full object data
                obj_data = conn.execute("SELECT * FROM objects WHERE id = ?", (row['id'],)).fetchone()
                manifest["objects"].append(dict(obj_data))
                
                # Get relations
                rels = conn.execute("SELECT * FROM relations WHERE from_id = ?", (row['id'],)).fetchall()
                for rel in rels:
                    manifest["relations"].append(dict(rel))
            
            zf.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
            conn.close()
            
        print(f"Export successful: {len(rows)} objects packaged.")

    def import_package(self, package_path):
        """Import objects from a ZIP package."""
        import zipfile
        package_path = Path(package_path)
        if not package_path.exists():
            print(f"Error: {package_path} not found.")
            return False
            
        print(f"Importing from {package_path}...")
        with zipfile.ZipFile(package_path, 'r') as zf:
            # 1. Load manifest
            if "manifest.json" not in zf.namelist():
                print("Error: Invalid package (missing manifest.json)")
                return False
                
            manifest = json.loads(zf.read("manifest.json").decode('utf-8'))
            
            # 2. Extract objects
            import_count = 0
            for member in zf.namelist():
                if member.startswith("objects/"):
                    # Extract relative to .eternal's parent to maintain structure
                    zf.extract(member, path=self.root_dir.parent)
                    import_count += 1
            
            # 3. Merge database records
            conn = sqlite3.connect(self.db_path)
            for obj in manifest.get("objects", []):
                conn.execute('''
                    INSERT OR REPLACE INTO objects 
                    (id, data_type, content_hash, signature, version, created_at, updated_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (obj['id'], obj['data_type'], obj['content_hash'], obj['signature'], 
                      obj['version'], obj['created_at'], obj['updated_at'], obj['metadata']))
            
            for rel in manifest.get("relations", []):
                conn.execute("INSERT OR REPLACE INTO relations (from_id, to_id, rel_type) VALUES (?, ?, ?)",
                             (rel['from_id'], rel['to_id'], rel['rel_type']))
            
            conn.commit()
            conn.close()
            
        print(f"Import successful: {len(manifest.get('objects', []))} objects merged.")
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser(prog="eternal", description="EternalCore: Generic Object Persistence Engine")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize a new repository")
    init_parser.add_argument("--role", default="master", choices=["master", "contributor", "mirror"], help="Node role")
    init_parser.add_argument("--federation-id", help="Federation ID to join (leave empty to create new)")
    init_parser.add_argument("--mirror-dir", help="Path to a local mirror backup directory")

    # put
    put_parser = subparsers.add_parser("put", help="Store an object")
    put_parser.add_argument("id", help="Object ID")
    put_parser.add_argument("content", help="Object content (string or file path)")
    put_parser.add_argument("--type", default="blob", help="Data type")
    put_parser.add_argument("--meta", help="Metadata (JSON string)")
    put_parser.add_argument("--relations", help="Relations (JSON string, list of [to_id, type])")

    # get
    get_parser = subparsers.add_parser("get", help="Retrieve an object")
    get_parser.add_argument("id", help="Object ID")
    get_parser.add_argument("--raw", action="store_true", help="Output raw bytes")

    # list/search
    list_parser = subparsers.add_parser("list", help="List or search objects")
    list_parser.add_argument("query", nargs="?", help="Search query")
    list_parser.add_argument("--type", help="Filter by data type")

    # rollback
    rb_parser = subparsers.add_parser("rollback", help="Roll back an object to a specific version")
    rb_parser.add_argument("id", help="Object ID")
    rb_parser.add_argument("version", type=int, help="Version number")

    # audit
    subparsers.add_parser("audit", help="Run a full system integrity audit")

    # sync
    sync_parser = subparsers.add_parser("sync", help="Synchronize with mirror storage")
    sync_parser.add_argument("--mirror", help="Override mirror directory")

    # push
    push_parser = subparsers.add_parser("push", help="Intelligent delta push to remote")
    push_parser.add_argument("remote", help="Remote repository path or URL")

    # pull
    pull_parser = subparsers.add_parser("pull", help="Intelligent delta pull from remote")
    pull_parser.add_argument("remote", help="Remote repository path or URL")

    # peer
    peer_parser = subparsers.add_parser("peer", help="Manage network peers")
    peer_sub = peer_parser.add_subparsers(dest="peer_command", help="Peer commands")
    
    peer_add = peer_sub.add_parser("add", help="Add a network peer")
    peer_add.add_argument("name", help="Peer name")
    peer_add.add_argument("url", help="Peer repository URL/path")
    
    peer_sub.add_parser("list", help="List all network peers")
    
    peer_sub.add_parser("sync", help="Force broadcast to all peers")

    peer_subscribe = peer_sub.add_parser("subscribe", help="Set selective sync filters (Interests)")
    peer_subscribe.add_argument("key", help="Filter key (e.g., 'data_type', 'path', 'metadata.category')")
    peer_subscribe.add_argument("value", help="Filter value (e.g., 'doc', 'src/', 'Science')")
    peer_subscribe.add_argument("--remove", action="store_true", help="Remove the filter instead of adding")

    # health
    subparsers.add_parser("health", help="Check system health")

    # rebuild
    subparsers.add_parser("rebuild", help="Rebuild index from physical storage")

    # visualize
    vis_parser = subparsers.add_parser("visualize", help="Visualize object relations")
    vis_parser.add_argument("id", help="Root object ID")

    # validate
    val_parser = subparsers.add_parser("validate", help="Validate relation integrity")
    val_parser.add_argument("id", help="Object ID")

    # export
    exp_parser = subparsers.add_parser("export", help="Export objects to a package")
    exp_parser.add_argument("output", help="Output ZIP path")
    exp_parser.add_argument("--type", help="Filter by data type")

    # import
    imp_parser = subparsers.add_parser("import", help="Import objects from a package")
    imp_parser.add_argument("package", help="ZIP package path")

    # Global options
    parser.add_argument("--config", help="Path to config.json")
    parser.add_argument("--root", help="Override repository root")

    args = parser.parse_args()
    
    if args.command == "init":
        EternalCore.init_repo(args.root or ".", role=args.role, federation_id=args.federation_id, mirror_dir=args.mirror_dir)
        return

    # Find repository root
    repo_root = args.root or EternalCore.find_repo_root()
    if not repo_root:
        print("Error: Not a repository (or any of the parent directories): .eternal")
        sys.exit(1)
        
    eternal_dir = Path(repo_root) / ".eternal"
    
    # Load config
    config = {}
    config_path = args.config or (eternal_dir / "config.json")
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
            
    # Initialize Core
    core = EternalCore(
        root_dir=eternal_dir,
        mirror_dir=args.mirror if hasattr(args, 'mirror') and args.mirror else config.get('mirror_dir'),
        secret_key=config.get('secret_key'),
        master_key=config.get('master_key'),
        app_name=config.get('app_name', 'EternalCore')
    )
    
    try:
        if args.command == "put":
            meta = json.loads(args.meta) if args.meta else {}
            rels = json.loads(args.relations) if args.relations else []
            content_data = args.content
            if os.path.exists(args.content):
                with open(args.content, 'rb') as f:
                    content_data = f.read()
            core.put(args.id, content_data, metadata=meta, data_type=args.type, relations=rels)
            
        elif args.command == "get":
            res = core.get(args.id)
            if res:
                if args.raw:
                    sys.stdout.buffer.write(res['content'])
                else:
                    print(f"ID: {args.id}")
                    print(f"Type: {res['data_type']} (v{res['version']})")
                    print(f"Metadata: {json.dumps(res['metadata'], indent=2)}")
                    print("-" * 20)
                    try:
                        if isinstance(res['content'], bytes):
                            print(res['content'].decode('utf-8'))
                        else:
                            print(res['content'])
                    except UnicodeDecodeError:
                        print(f"<Binary Data: {len(res['content'])} bytes>")
            else:
                print(f"Error: Object {args.id} not found.")
                sys.exit(1)
                
        elif args.command == "list":
            results = core.search(query=args.query, data_type=args.type)
            print(f"{'ID':<20} | {'Type':<10} | {'Ver':<5} | {'Created At'}")
            print("-" * 60)
            for r in results:
                print(f"{r['id']:<20} | {r['data_type']:<10} | {r['version']:<5} | {r['created_at']}")
                
        elif args.command == "rollback":
            if core.rollback(args.id, args.version):
                print(f"Successfully rolled back {args.id} to v{args.version}")
            else:
                sys.exit(1)
                
        elif args.command == "audit":
            if not core.audit_all():
                sys.exit(1)
                
        elif args.command == "sync":
            if not core.sync_to_mirror():
                sys.exit(1)
                
        elif args.command == "push":
            if not core.push(args.remote):
                sys.exit(1)
                
        elif args.command == "pull":
            if not core.pull(args.remote):
                sys.exit(1)
                
        elif args.command == "peer":
            if args.peer_command == "add":
                core.add_peer(args.name, args.url)
            elif args.peer_command == "list":
                conn = sqlite3.connect(core.db_path)
                conn.row_factory = sqlite3.Row
                peers = conn.execute("SELECT * FROM peers").fetchall()
                print(f"{'NAME':<15} {'URL':<40} {'LAST SEEN':<20}")
                print("-" * 75)
                for p in peers:
                    print(f"{p['name']:<15} {p['url']:<40} {p['last_seen']:<20}")
                conn.close()
            elif args.peer_command == "sync":
                core.broadcast()
            elif args.peer_command == "subscribe":
                conn = sqlite3.connect(core.db_path)
                if args.remove:
                    conn.execute("DELETE FROM subscriptions WHERE filter_key = ? AND filter_value = ?", (args.key, args.value))
                    print(f"Filter removed: {args.key} = {args.value}")
                else:
                    conn.execute("INSERT OR REPLACE INTO subscriptions (filter_key, filter_value) VALUES (?, ?)", (args.key, args.value))
                    print(f"Filter added: {args.key} = {args.value}")
                conn.commit()
                conn.close()
                
        elif args.command == "health":
            health = core.health_check()
            print(json.dumps(health, indent=2))
            return # Exit after printing JSON
            
        elif args.command == "rebuild":
            core.rebuild_index()
            
        elif args.command == "visualize":
            core.visualize_relations(args.id)
            
        elif args.command == "validate":
            ok, missing = core.validate_relations(args.id)
            if ok:
                print(f"Relation integrity for {args.id}: OK")
            else:
                print(f"Relation integrity for {args.id}: FAILED. Missing: {missing}")
                sys.exit(1)

        elif args.command == "export":
            core.export_package(args.output, data_type=args.type)

        elif args.command == "import":
            core.import_package(args.package)

    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
