import os
import json
import sqlite3
import hashlib
import shutil
import hmac
import tempfile
import logging
import zlib
import base64
from datetime import datetime
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    Fernet = None
    hashes = None
    PBKDF2HMAC = None

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

class EternalCore:
    def __init__(self, root_dir, mirror_dir=None, secret_key=None, master_key=None, app_name="EternalCore"):
        self.root_dir = Path(root_dir).resolve()
        self.objects_dir = self.root_dir / "objects"
        self.db_path = self.root_dir / "metadata" / f"{app_name.lower()}_index.db"
        self.app_name = app_name
        
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
        if master_key and HAS_CRYPTO and PBKDF2HMAC is not None and hashes is not None and Fernet is not None:
            salt = b'seed-plan-salt-2026' # In production, use a unique salt per installation
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
            self.fernet = Fernet(key)
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
        
        # Generic entries table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                title TEXT,
                category TEXT,
                description TEXT,
                content_hash TEXT,
                signature TEXT,
                importance INTEGER,
                mime_type TEXT,
                version INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                custom_fields TEXT
            )
        ''')
        
        # History table for version control
        conn.execute('''
            CREATE TABLE IF NOT EXISTS history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT,
                content_hash TEXT,
                version INTEGER,
                timestamp TEXT,
                metadata TEXT,
                FOREIGN KEY(entry_id) REFERENCES entries(id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS dependencies (
                entry_id TEXT,
                depends_on_id TEXT,
                FOREIGN KEY(entry_id) REFERENCES entries(id),
                FOREIGN KEY(depends_on_id) REFERENCES entries(id)
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
        
        # Composite indexes for performance
        conn.execute('CREATE INDEX IF NOT EXISTS idx_taxonomy_title ON entries(taxonomy_path, title)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_hash_version ON history(content_hash, version)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_entry_history ON history(entry_id, version)')
        
        conn.commit()
        conn.close()

    def safe_add_entry(self, entry_data, content, max_retries=3):
        """Wrapper for add_entry with automatic retry on concurrency conflicts."""
        import time
        import random
        
        for attempt in range(max_retries):
            try:
                return self.add_entry(entry_data, content)
            except Exception as e:
                if "Write Conflict" in str(e) and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 0.1 + random.uniform(0, 0.1)
                    logger.warning(f"Concurrency conflict for {entry_data.get('id')}. Retrying in {wait_time:.2f}s... (Attempt {attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                else:
                    raise

    def calculate_merkle_root(self):
        """Calculate the Merkle Root using a cached, level-by-level approach."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. Get current leaf hashes (ordered by ID for determinism)
        cursor.execute("SELECT content_hash FROM entries ORDER BY id")
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
        """Generate a signature to ensure the entry was created by the Seed authority."""
        return hmac.new(self.secret_key.encode(), content_hash.encode(), hashlib.sha256).hexdigest()



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
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            
            if meta.get('encryption'):
                content = self._decrypt(content)
                
            if meta.get('compression') == 'zlib':
                content = zlib.decompress(content)
        
        return content

    def get_content(self, entry_id, lang=None):
        """Retrieve content for an entry, automatically selecting primary language if not specified."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT content_hash FROM entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise Exception(f"Entry {entry_id} not found.")
            
        try:
            content_hashes = json.loads(row['content_hash'])
            target_lang = lang or ('zh' if 'zh' in content_hashes else list(content_hashes.keys())[0])
            target_hash = content_hashes.get(target_lang)
        except:
            # Legacy support if content_hash is not JSON
            target_hash = row['content_hash']
        
        if not target_hash:
            raise Exception(f"Language {lang} not available for entry {entry_id}")
            
        return self.get_object_content(target_hash)

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
                self._atomic_write(meta_path, json.dumps(metadata, indent=2, ensure_ascii=False))
                
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

    def get_entry(self, entry_id):
        """Retrieve entry details by ID."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def add_entry(self, entry_data, content):
        """Add or update an entry with multi-language support and version control."""
        # 1. Handle multi-language title
        title_input = entry_data.get('title', 'Untitled')
        if isinstance(title_input, str):
            titles = {'en': title_input}
        elif isinstance(title_input, dict):
            titles = title_input
        else:
            raise ValueError("Title must be str or dict")
            
        category = entry_data.get('category', 'General')
        description = entry_data.get('description', '')
        importance = entry_data.get('importance', 5)
        dependencies = entry_data.get('dependencies', [])
        compress = entry_data.get('compress', True)
        encrypt = entry_data.get('encrypt', False)
        custom_fields = entry_data.get('custom_fields', {})
        
        # 2. Handle multi-language content
        contents = content if isinstance(content, dict) else {'en': content}
        content_hashes = {}
        signatures = {}
        
        for lang, lang_content in contents.items():
            # Store object with metadata
            obj_meta = {
                "category": category,
                "lang": lang,
                "timestamp": datetime.now().isoformat(),
                "encryption": encrypt,
                "compression": "zlib" if compress else None
            }
            h = self._store_object(lang_content, metadata=obj_meta, compress=compress, encrypt=encrypt)
            content_hashes[lang] = h
            signatures[lang] = self._sign_content(h)
            
        # 3. Determine primary data for database (Scheme A)
        primary_lang = 'zh' if 'zh' in contents else (list(contents.keys())[0] if contents else 'en')
        primary_hash = content_hashes.get(primary_lang, '')
        primary_signature = signatures.get(primary_lang, '')
        primary_title = titles.get(primary_lang, list(titles.values())[0])

        entry_id = entry_data.get('id') or f"E-{primary_hash[:12]}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT version FROM entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            current_version = row[0] if row else 0
            new_version = current_version + 1
            now_str = datetime.now().isoformat()
            
            meta_payload = {
                "id": entry_id,
                "titles": titles,
                "category": category,
                "description": description,
                "content_hashes": content_hashes,
                "signatures": signatures,
                "importance": importance,
                "dependencies": dependencies,
                "created_at": entry_data.get('created_at') or now_str,
                "version": new_version,
                "metadata_version": 4,
                "compress": compress,
                "encrypt": encrypt,
                "custom_fields": custom_fields
            }

            # Store meta next to primary object
            shard_dir = self.objects_dir / primary_hash[0:2] / primary_hash[2:4]
            meta_path = shard_dir / f"{primary_hash}.meta"
            self._atomic_write(meta_path, json.dumps(meta_payload, indent=2, ensure_ascii=False))

            # 2. Store physical objects for each language
            for lang, lang_content in contents.items():
                lang_meta = meta_payload.copy()
                lang_meta['lang'] = lang
                self._store_object(lang_content, metadata=lang_meta, compress=compress, encrypt=encrypt)
            
            # 3. Database index update
            # Store titles and hashes as JSON in DB for flexibility
            titles_json = json.dumps(titles, ensure_ascii=False)
            hashes_json = json.dumps(content_hashes, ensure_ascii=False)
            
            if current_version == 0:
                cursor.execute('''
                    INSERT INTO entries 
                    (id, title, category, description, content_hash, signature, importance, mime_type, version, created_at, updated_at, custom_fields)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (entry_id, titles_json, category, description, hashes_json, primary_signature, importance, 'text/markdown', new_version, meta_payload["created_at"], now_str, json.dumps(custom_fields)))
            else:
                cursor.execute('''
                    UPDATE entries SET 
                    title=?, category=?, description=?, content_hash=?, signature=?, importance=?, version=?, updated_at=?, custom_fields=?
                    WHERE id=? AND version=?
                ''', (titles_json, category, description, hashes_json, primary_signature, importance, new_version, now_str, json.dumps(custom_fields), entry_id, current_version))
                
                if cursor.rowcount == 0:
                    raise Exception(f"Write Conflict: Entry {entry_id} was modified by another process.")

            # 4. History
            cursor.execute('''
                INSERT INTO history (entry_id, content_hash, version, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (entry_id, hashes_json, new_version, now_str))
            
            if dependencies:
                cursor.execute('DELETE FROM dependencies WHERE entry_id = ?', (entry_id,))
                for dep_id in dependencies:
                    cursor.execute('INSERT OR IGNORE INTO dependencies (entry_id, depends_on_id) VALUES (?, ?)', (entry_id, dep_id))
            
            conn.commit()
            
            # 5. Commit State (Blockchain-like state update)
            self.commit_state()
            
            logger.info(f"Success: Added/Updated [{title}] to v{new_version}")
            return entry_id
        except Exception as e:
            logger.error(f"Error adding entry: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()

    def rollback(self, entry_id, target_version):
        """Roll back an entry to a specific version from history."""
        logger.info(f"Initiating rollback for {entry_id} to version {target_version}")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            # 1. Find the version in history
            cursor.execute("SELECT * FROM history WHERE entry_id = ? AND version = ?", (entry_id, target_version))
            hist_row = cursor.fetchone()
            if not hist_row:
                logger.error(f"Version {target_version} not found for entry {entry_id}")
                return False
            
            # In Scheme A, history.content_hash is the primary hash at that time
            primary_hash = hist_row['content_hash']
            
            # 2. Get metadata from sidecar to restore properties
            shard_dir = self.objects_dir / primary_hash[0:2] / primary_hash[2:4]
            meta_path = shard_dir / f"{primary_hash}.meta"
            
            if not meta_path.exists():
                logger.error(f"Sidecar metadata missing for hash {primary_hash}. Cannot restore properties.")
                return False
                
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            
            # 3. Perform the rollback update
            cursor.execute("SELECT version FROM entries WHERE id = ?", (entry_id,))
            current_version = cursor.fetchone()[0]
            new_version = current_version + 1
            now_str = datetime.now().isoformat()
            
            # Determine primary signature and titles for database index
            # Scheme A: Store only primary language title and hash in DB
            primary_lang = meta.get('lang', 'en')
            primary_sig = meta['signatures'].get(primary_lang)
            primary_title = meta['titles'].get(primary_lang, list(meta['titles'].values())[0])
            
            category = meta.get('category', 'General')
            cursor.execute('''
                UPDATE entries SET 
                title=?, category=?, description=?, content_hash=?, signature=?, importance=?, version=?, updated_at=?, custom_fields=?
                WHERE id=?
            ''', (primary_title, category, meta['description'], primary_hash, primary_sig, meta['importance'], new_version, now_str, json.dumps(meta.get('custom_fields', {})), entry_id))
            
            # 4. Record the rollback event in history
            cursor.execute('''
                INSERT INTO history (entry_id, content_hash, version, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (entry_id, primary_hash, new_version, now_str, json.dumps(meta)))
            
            conn.commit()
            self.commit_state()
            logger.info(f"Rollback successful: {entry_id} v{new_version} (restored from v{target_version})")
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Rollback failed: {e}")
            return False
        finally:
            conn.close()

    def validate_dependencies(self, entry_id, visited=None):
        """Recursively ensure the dependency chain is complete and avoid orphans."""
        if visited is None:
            visited = set()
        
        if entry_id in visited:
            return True, []
        
        visited.add(entry_id)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if entry exists
        cursor.execute("SELECT id FROM entries WHERE id = ?", (entry_id,))
        if not cursor.fetchone():
            conn.close()
            return False, [entry_id]
        
        # Get dependencies
        cursor.execute("SELECT depends_on_id FROM dependencies WHERE entry_id = ?", (entry_id,))
        deps = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        missing_all = []
        for dep_id in deps:
            ok, missing = self.validate_dependencies(dep_id, visited)
            if not ok:
                missing_all.extend(missing)
        
        return len(missing_all) == 0, list(set(missing_all))

    def visualize_dependencies(self, entry_id, level=0, visited=None):
        """Generate a text-based dependency graph visualization."""
        if visited is None:
            visited = set()
            
        entry = self.get_entry(entry_id)
        if not entry:
            print("  " * level + f"[-] {entry_id} (MISSING)")
            return

        # Handle multi-language title if it's a JSON string
        title_data = entry['title']
        try:
            title_dict = json.loads(title_data)
            title = title_dict.get('zh') or title_dict.get('en') or list(title_dict.values())[0]
        except:
            title = title_data

        print("  " * level + f"[+] {title} ({entry_id})")
        
        if entry_id in visited:
            print("  " * (level + 1) + " (circular dependency detected)")
            return
            
        visited.add(entry_id)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT depends_on_id FROM dependencies WHERE entry_id = ?", (entry_id,))
        deps = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        for dep_id in deps:
            self.visualize_dependencies(dep_id, level + 1, visited)

    def health_check(self):
        """Perform a comprehensive system health check."""
        checks = {
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
        """Comprehensive audit of all entries in the index vs physical storage."""
        print("Starting comprehensive civilization audit...")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM entries")
        rows = cursor.fetchall()
        
        stats = {"total": 0, "healthy": 0, "repaired": 0, "corrupted": 0}
        
        for row in rows:
            stats["total"] += 1
            h = row['content_hash']
            primary = self.objects_dir / h[0:2] / h[2:4] / h
            mirror = self.mirror_dir / h[0:2] / h[2:4] / h if self.mirror_dir else None
            
            # 1. Verify Signature
            if row['signature'] != self._sign_content(h):
                print(f"CRITICAL: Entry {row['id']} has INVALID SIGNATURE (Tampering detected!)")
                stats["corrupted"] += 1
                continue

            # 2. Check Integrity & Bi-directional Repair
            # Fixed linter error by ensuring mirror is not None before path operations
            primary_ok = primary.exists() and self._calculate_hash(open(primary, 'rb').read()) == h
            mirror_ok = False
            if mirror:
                mirror_ok = mirror.exists() and self._calculate_hash(open(mirror, 'rb').read()) == h
            
            if not primary_ok and mirror_ok and mirror:
                print(f"Repair: Recovering primary {h[:8]} from mirror...")
                primary.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(mirror, primary)
                stats["repaired"] += 1
            elif primary_ok and mirror and not mirror_ok:
                print(f"Sync: Backing up {h[:8]} to mirror...")
                mirror.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(primary, mirror)
                # Also sync the meta file
                if primary.with_suffix('.meta').exists():
                    shutil.copy2(primary.with_suffix('.meta'), mirror.with_suffix('.meta'))
                stats["healthy"] += 1
            elif not primary_ok and (not mirror or not mirror_ok):
                print(f"ERROR: Entry {row['id']} PERMANENTLY LOST.")
                stats["corrupted"] += 1
            else:
                stats["healthy"] += 1
        
        conn.close()
        print(f"Audit Complete: {stats}")
        return stats

    def rebuild_index(self):
         """Rebuild the SQLite index from all .meta files in the objects directory."""
         print("Rebuilding index from physical sidecar files...")
         conn = sqlite3.connect(self.db_path)
         # Ensure schema is up to date before rebuild
         conn.execute('DROP TABLE IF EXISTS entries')
         conn.execute('DROP TABLE IF EXISTS dependencies')
         conn.execute('DROP TABLE IF EXISTS history')
         conn.close()
         self._init_db()
         
         conn = sqlite3.connect(self.db_path)
         cursor = conn.cursor()
         
         for meta_file in self.objects_dir.glob("**/*.meta"):
             # Skip object-level meta files (those that don't have an 'id' field for an entry)
             with open(meta_file, 'r', encoding='utf-8') as f:
                 m = json.load(f)
                 if 'id' not in m: continue # It's an object-level meta, not entry-level
                 
                 ver = m.get('version', 1)
                 
                 # Scheme A: Store only primary language title and hash in DB
                       # In entry-level sidecar, titles is a dict, content_hashes is a dict
                       titles = m.get('titles', {'en': m.get('title', 'Untitled')})
                       content_hashes = m.get('content_hashes', {'en': m.get('content_hash', '')})
                       signatures = m.get('signatures', {'en': m.get('signature', '')})
                       category = m.get('category', 'General')
                       custom_fields = m.get('custom_fields', {})
                       
                       primary_lang = 'zh' if 'zh' in content_hashes else (list(content_hashes.keys())[0] if content_hashes else 'en')
                       primary_hash = content_hashes.get(primary_lang, '')
                       primary_title = titles.get(primary_lang, list(titles.values())[0] if titles else 'Untitled')
                       primary_sig = signatures.get(primary_lang, '')

                       cursor.execute('''
                           INSERT OR REPLACE INTO entries 
                           (id, title, category, description, content_hash, signature, importance, version, created_at, custom_fields)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ''', (m['id'], primary_title, category, m['description'], primary_hash, primary_sig, m['importance'], ver, m['created_at'], json.dumps(custom_fields)))
                 
                 # Populate history with the version from sidecar
                 cursor.execute('''
                    INSERT OR IGNORE INTO history (entry_id, content_hash, version, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?)
                 ''', (m['id'], primary_hash, ver, m['created_at'], json.dumps(m)))

                 for dep_id in m.get('dependencies', []):
                     cursor.execute('INSERT INTO dependencies (entry_id, depends_on_id) VALUES (?, ?)', (m['id'], dep_id))
         
         conn.commit()
         conn.close()
         print("Index rebuilt successfully.")

    def search(self, query=None, taxonomy_prefix=None):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        sql = "SELECT * FROM entries WHERE 1=1"
        params = []
        if query:
            sql += " AND (title LIKE ? OR description LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])
        if taxonomy_prefix:
            sql += " AND taxonomy_path LIKE ?"
            params.append(f"{taxonomy_prefix}%")
            
        cursor.execute(sql, params)
        results = cursor.fetchall()
        conn.close()
        return results

    def verify_state_chain(self):
        """Verify the integrity of the entire state chain (Blockchain validation)."""
        print("Verifying state chain integrity...")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT height, state_hash, merkle_root, prev_state_hash FROM state_chain ORDER BY height ASC")
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
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

    def export_package(self, output_path, taxonomy_prefix=None):
        """Export a set of entries into a secure package with a signed manifest."""
        print(f"Exporting package to {output_path}...")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM entries"
        params = []
        if taxonomy_prefix:
            query += " WHERE taxonomy_path LIKE ?"
            params.append(f"{taxonomy_prefix}%")
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        if not rows:
            print("No entries found to export.")
            return
            
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            export_data_dir = tmp_path / "objects"
            export_data_dir.mkdir()
            
            manifest = {
                "version": "2.0",
                "exported_at": datetime.now().isoformat(),
                "taxonomy_filter": taxonomy_prefix,
                "files": []
            }
            
            for row in rows:
                h = row['content_hash']
                # Copy object
                src_obj = self.objects_dir / h[0:2] / h[2:4] / h
                src_meta = src_obj.with_suffix('.meta')
                
                if src_obj.exists():
                    dest_obj = export_data_dir / h
                    shutil.copy2(src_obj, dest_obj)
                    manifest["files"].append({
                        "path": f"objects/{h}",
                        "hash": h,
                        "type": "object"
                    })
                
                if src_meta.exists():
                    dest_meta = export_data_dir / f"{h}.meta"
                    shutil.copy2(src_meta, dest_meta)
                    # We don't hash the meta itself in the manifest, 
                    # but it's protected by the entry's signature inside it
                    manifest["files"].append({
                        "path": f"objects/{h}.meta",
                        "type": "metadata"
                    })
            
            # Sign the manifest
            manifest_content = json.dumps(manifest, indent=2, ensure_ascii=False)
            manifest_hash = self._calculate_hash(manifest_content)
            manifest_sig = self._sign_content(manifest_hash)
            
            with open(tmp_path / "manifest.json", "w", encoding='utf-8') as f:
                f.write(manifest_content)
            
            with open(tmp_path / "signature.txt", "w") as f:
                f.write(f"{manifest_hash}\n{manifest_sig}")
            
            # Create final ZIP
            shutil.make_archive(output_path.replace('.zip', ''), 'zip', tmp_path)
            print(f"Export Complete: {len(rows)} entries packaged.")

    def import_package(self, package_path):
        """Import entries from a secure package, with resume capability and integrity checks."""
        print(f"Importing package from {package_path}...")
        if not os.path.exists(package_path):
            print("Error: Package file not found.")
            return

        # Resume mechanism: Track progress in a journal file
        package_id = hashlib.sha256(str(package_path).encode()).hexdigest()[:16]
        journal_path = self.root_dir / "metadata" / f"import_{package_id}.journal"
        finished_hashes = set()
        if journal_path.exists():
            with open(journal_path, 'r') as f:
                finished_hashes = set(line.strip() for line in f if line.strip())
            print(f"Resuming import: {len(finished_hashes)} items already processed.")

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                shutil.unpack_archive(package_path, tmpdir)
            except Exception as e:
                print(f"Error unpacking package: {e}")
                return
                
            tmp_path = Path(tmpdir)
            
            # 1. Verify Manifest Signature
            manifest_file = tmp_path / "manifest.json"
            sig_file = tmp_path / "signature.txt"
            if not manifest_file.exists() or not sig_file.exists():
                print("Error: Invalid package format (missing manifest or signature).")
                return
                
            with open(sig_file, "r") as f:
                lines = f.read().splitlines()
                if len(lines) < 2:
                    print("Error: Invalid signature format.")
                    return
                m_hash, m_sig = lines[0], lines[1]
                
            with open(manifest_file, "r", encoding='utf-8') as f:
                m_content = f.read()
                if self._calculate_hash(m_content) != m_hash:
                    print("Error: Manifest hash mismatch!")
                    return
                if self._sign_content(m_hash) != m_sig:
                    print("Error: Manifest signature INVALID! Package may be tampered.")
                    return
            
            manifest = json.loads(m_content)
            
            # 2. Process Files with Journaling
            import_count = 0
            skipped_count = 0
            
            # Sort files to ensure deterministic order if resuming
            files_to_process = [f for f in manifest["files"] if f["type"] == "object"]
            
            for file_info in files_to_process:
                h = file_info["hash"]
                if h in finished_hashes:
                    skipped_count += 1
                    continue
                    
                obj_path = tmp_path / file_info["path"]
                meta_path = obj_path.with_suffix('.meta')
                
                if not obj_path.exists() or not meta_path.exists():
                    print(f"Warning: Skipping missing object {h}")
                    continue
                    
                # Verify content hash before importing
                with open(obj_path, 'rb') as f:
                    if self._calculate_hash(f.read()) != h:
                        print(f"Error: Hash mismatch for {h}! Skipping.")
                        continue
                        
                # Load metadata
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                
                # Add to local store using safe_add_entry for concurrency protection
                with open(obj_path, 'rb') as f:
                    content = f.read()
                    try:
                        # Ensure we use the metadata from the package but respect local versioning
                        self.safe_add_entry(meta, content)
                        
                        # Update Journal after successful add
                        with open(journal_path, 'a') as f_j:
                            f_j.write(f"{h}\n")
                        import_count += 1
                    except Exception as e:
                        logger.error(f"Failed to import {h}: {e}")
                        break 
            
            # 3. Cleanup Journal if finished
            if import_count + skipped_count >= len(files_to_process):
                if journal_path.exists():
                    os.remove(journal_path)
                print(f"Import Complete: {import_count} added, {skipped_count} skipped.")
            else:
                print(f"Import Interrupted: {import_count} items processed. Run again to resume.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Seed Core Manager v2")
    parser.add_argument("cmd", choices=["add", "search", "rebuild", "audit", "sync", "verify_chain", "export", "import", "rollback", "history", "validate", "graph", "health", "cat"])
    parser.add_argument("args", nargs="*")
    parser.add_argument("--config", help="Path to config.json")
    parser.add_argument("--mirror", help="Path to mirror directory")
    parser.add_argument("--taxonomy", help="Taxonomy prefix for export")
    parser.add_argument("--output", help="Output path for export package")
    parser.add_argument("--package", help="Package path for import")
    parser.add_argument("--version", type=int, help="Target version for rollback")
    parser.add_argument("--lang", help="Target language for add/search/cat")
    parser.add_argument("--master-key", help="Master key for encryption/decryption")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt content")
    
    parsed = parser.parse_args()
    
    if parsed.config:
        core = EternalCore.from_config(parsed.config)
    else:
        core = EternalCore("d:/Seed", mirror_dir=parsed.mirror, secret_key="SEED_PLAN_2026_SECURE_KEY", master_key=parsed.master_key, app_name="SeedPlan")
    
    if parsed.cmd == "add":
        if len(parsed.args) < 4:
            print("Usage: add <taxonomy> <title> <description> <file_path> [--lang zh] [--encrypt]")
        else:
            lang = parsed.lang or 'en'
            with open(parsed.args[3], 'r', encoding='utf-8') as f:
                content = f.read()
            entry_id = parsed.args[1].lower().replace(' ', '_')
            core.add_entry({
                "id": entry_id,
                "title": {lang: parsed.args[1]},
                "taxonomy_path": parsed.args[0],
                "description": parsed.args[2],
                "importance": 5,
                "dependencies": [],
                "encrypt": parsed.encrypt
            }, {lang: content})
    elif parsed.cmd == "cat":
        if len(parsed.args) < 1:
            print("Usage: cat <entry_id> [--lang zh]")
        else:
            try:
                content = core.get_content(parsed.args[0], lang=parsed.lang)
                print(content.decode('utf-8'))
            except Exception as e:
                print(f"Error: {e}")
    elif parsed.cmd == "health":
        results = core.health_check()
        print(json.dumps(results, indent=2))
    elif parsed.cmd == "search":
        q = parsed.args[0] if parsed.args else ""
        results = core.search(query=q)
        for r in results:
            try:
                titles = json.loads(r['title'])
                title = titles.get(parsed.lang) or titles.get('zh') or titles.get('en') or list(titles.values())[0]
            except:
                title = r['title']
            print(f"[{r['taxonomy_path']}] {title} (v{r['version']}, Hash: {r['content_hash'][:8]})")
    elif parsed.cmd == "validate":
        if len(parsed.args) < 1:
            print("Usage: validate <entry_id>")
        else:
            ok, missing = core.validate_dependencies(parsed.args[0])
            if ok:
                print(f"Success: All dependencies for {parsed.args[0]} are present.")
            else:
                print(f"Error: Missing dependencies for {parsed.args[0]}: {missing}")
    elif parsed.cmd == "graph":
        if len(parsed.args) < 1:
            print("Usage: graph <entry_id>")
        else:
            core.visualize_dependencies(parsed.args[0])
    elif parsed.cmd == "rollback":
        if len(parsed.args) < 2:
            print("Usage: rollback <entry_id> <version>")
        else:
            core.rollback(parsed.args[0], int(parsed.args[1]))
    elif parsed.cmd == "history":
        if len(parsed.args) < 1:
            print("Usage: history <entry_id>")
        else:
            conn = sqlite3.connect(core.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM history WHERE entry_id = ? ORDER BY version DESC", (parsed.args[0],))
            rows = cursor.fetchall()
            print(f"History for {parsed.args[0]}:")
            for row in rows:
                print(f"  v{row['version']} | {row['timestamp']} | Hash: {row['content_hash'][:12]}")
            conn.close()
    elif parsed.cmd == "rebuild":
        core.rebuild_index()
    elif parsed.cmd == "verify_chain":
        core.verify_state_chain()
    elif parsed.cmd == "audit":
        core.audit_all()
    elif parsed.cmd == "sync":
        if not parsed.mirror:
            print("Error: --mirror required for sync.")
        else:
            core.audit_all()
    elif parsed.cmd == "export":
        if not parsed.output:
            print("Error: --output required for export.")
        else:
            core.export_package(parsed.output, parsed.taxonomy)
    elif parsed.cmd == "import":
        if not parsed.package:
            print("Error: --package required for import.")
        else:
            core.import_package(parsed.package)
