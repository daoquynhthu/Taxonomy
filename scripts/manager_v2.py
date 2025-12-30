import os
import json
import sqlite3
import hashlib
import shutil
import hmac
import tempfile
import logging
from datetime import datetime
from pathlib import Path

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

class SeedCore:
    def __init__(self, root_dir, mirror_dir=None, secret_key=None):
        self.root_dir = Path(root_dir).resolve()
        self.objects_dir = self.root_dir / "objects"
        self.db_path = self.root_dir / "metadata" / "seed_index.db"
        
        # Mirror configuration
        if mirror_dir:
            self.mirror_dir = Path(mirror_dir).resolve()
            if os.name == 'nt' and self.mirror_dir.drive == self.root_dir.drive:
                logger.warning("Mirror is on the same physical drive as source.")
        else:
            self.mirror_dir = None
            
        self.secret_key = secret_key or "humanity-eternal-2026"
        self._init_db()
        logger.info(f"SeedCore initialized at {self.root_dir}")

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

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        
        # Entries with optimistic locking (version column)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                title TEXT,
                taxonomy_path TEXT,
                description TEXT,
                content_hash TEXT,
                signature TEXT,
                importance INTEGER,
                mime_type TEXT,
                version INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
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
        cursor.execute("DELETE FROM merkle_cache WHERE level = ?", (level,))
        cursor.execute("INSERT INTO merkle_cache (level, pos, hash) VALUES (?, 0, ?)", (level, root))
        
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



    def _store_object(self, content, metadata=None):
        h = self._calculate_hash(content)
        # Sharding: objects/ab/cd/ef...
        shard_dir = self.objects_dir / h[0:2] / h[2:4]
        shard_dir.mkdir(parents=True, exist_ok=True)
        obj_path = shard_dir / h
        meta_path = shard_dir / f"{h}.meta"
        
        # Performance: Only write if not exists (Deduplication)
        # Atomic write using a temporary file
        if not obj_path.exists():
            temp_path = obj_path.with_suffix('.tmp')
            with open(temp_path, 'wb') as f:
                if isinstance(content, str):
                    f.write(content.encode('utf-8'))
                else:
                    f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, obj_path)
        
        # Redundancy: Write a mirror copy (Configurable to different physical media)
        if self.mirror_dir:
            mirror_path = self.mirror_dir / h[0:2] / h[2:4] / h
            mirror_path.parent.mkdir(parents=True, exist_ok=True)
            if not mirror_path.exists():
                shutil.copy2(obj_path, mirror_path)
            
            # Mirror the metadata too
            meta_mirror = mirror_path.with_suffix('.meta')
            if metadata and not meta_mirror.exists():
                temp_meta = meta_mirror.with_suffix('.meta.tmp')
                with open(temp_meta, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2, ensure_ascii=False)
                os.replace(temp_meta, meta_mirror)

        # Store Sidecar Metadata
        if metadata:
            temp_meta_path = meta_path.with_suffix('.meta.tmp')
            with open(temp_meta_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            os.replace(temp_meta_path, meta_path)
                
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
        """Add or update an entry with version control and optimistic locking."""
        title = entry_data.get('title', 'Untitled')
        taxonomy_path = entry_data.get('taxonomy_path', 'General')
        description = entry_data.get('description', '')
        importance = entry_data.get('importance', 5)
        dependencies = entry_data.get('dependencies', [])
        
        content_hash = self._calculate_hash(content)
        entry_id = entry_data.get('id') or f"S-{content_hash[:12]}"
        signature = self._sign_content(content_hash)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # 1. Concurrency Check (Optimistic Locking)
            cursor.execute("SELECT version FROM entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            current_version = row[0] if row else 0
            new_version = current_version + 1
            
            meta_payload = {
                "id": entry_id,
                "title": title,
                "taxonomy_path": taxonomy_path,
                "description": description,
                "content_hash": content_hash,
                "signature": signature,
                "importance": importance,
                "dependencies": dependencies,
                "created_at": entry_data.get('created_at') or datetime.now().isoformat(),
                "version": new_version,
                "metadata_version": 3
            }

            # 2. Physical storage with mirroring
            self._store_object(content, metadata=meta_payload)
            
            # 3. Database index update
            now_str = datetime.now().isoformat()
            if current_version == 0:
                cursor.execute('''
                    INSERT INTO entries 
                    (id, title, taxonomy_path, description, content_hash, signature, importance, mime_type, version, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (entry_id, title, taxonomy_path, description, content_hash, signature, importance, 'text/markdown', new_version, meta_payload["created_at"], now_str))
            else:
                cursor.execute('''
                    UPDATE entries SET 
                    title=?, taxonomy_path=?, description=?, content_hash=?, signature=?, importance=?, version=?, updated_at=?
                    WHERE id=? AND version=?
                ''', (title, taxonomy_path, description, content_hash, signature, importance, new_version, now_str, entry_id, current_version))
                
                if cursor.rowcount == 0:
                    raise Exception(f"Write Conflict: Entry {entry_id} was modified by another process (Optimistic Lock failed).")

            # 4. Record history for versioning
            cursor.execute('''
                INSERT INTO history (entry_id, content_hash, version, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (entry_id, content_hash, new_version, now_str))
            
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
            
            target_hash = hist_row['content_hash']
            
            # 2. Get metadata from sidecar to restore properties
            shard_dir = self.objects_dir / target_hash[0:2] / target_hash[2:4]
            meta_path = shard_dir / f"{target_hash}.meta"
            
            if not meta_path.exists():
                logger.error(f"Sidecar metadata missing for hash {target_hash}. Cannot restore properties.")
                return False
                
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            
            # 3. Perform the rollback update
            # Rollback itself creates a new version to preserve history chain
            cursor.execute("SELECT version FROM entries WHERE id = ?", (entry_id,))
            current_version = cursor.fetchone()[0]
            new_version = current_version + 1
            now_str = datetime.now().isoformat()
            
            cursor.execute('''
                UPDATE entries SET 
                title=?, taxonomy_path=?, description=?, content_hash=?, signature=?, importance=?, version=?, updated_at=?
                WHERE id=?
            ''', (meta['title'], meta['taxonomy_path'], meta['description'], target_hash, meta['signature'], meta['importance'], new_version, now_str, entry_id))
            
            # 4. Record the rollback event
            cursor.execute('''
                INSERT INTO history (entry_id, content_hash, version, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (entry_id, target_hash, new_version, now_str))
            
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
             with open(meta_file, 'r', encoding='utf-8') as f:
                 m = json.load(f)
                 ver = m.get('version', 1)
                 cursor.execute('''
                     INSERT OR REPLACE INTO entries 
                     (id, title, taxonomy_path, description, content_hash, signature, importance, mime_type, version, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ''', (m['id'], m['title'], m['taxonomy_path'], m['description'], m['content_hash'], m.get('signature'), m['importance'], 'text/markdown', ver, m['created_at']))
                 
                 # Populate history with the version from sidecar
                 cursor.execute('''
                    INSERT OR IGNORE INTO history (entry_id, content_hash, version, timestamp)
                    VALUES (?, ?, ?, ?)
                 ''', (m['id'], m['content_hash'], ver, m['created_at']))

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
    parser.add_argument("cmd", choices=["add", "search", "rebuild", "audit", "sync", "verify_chain", "export", "import", "rollback", "history"])
    parser.add_argument("args", nargs="*")
    parser.add_argument("--mirror", help="Path to mirror directory")
    parser.add_argument("--taxonomy", help="Taxonomy prefix for export")
    parser.add_argument("--output", help="Output path for export package")
    parser.add_argument("--package", help="Package path for import")
    parser.add_argument("--version", type=int, help="Target version for rollback")
    
    parsed = parser.parse_args()
    core = SeedCore("d:/Seed", mirror_dir=parsed.mirror, secret_key="SEED_PLAN_2026_SECURE_KEY")
    
    if parsed.cmd == "add":
        if len(parsed.args) < 4:
            print("Usage: add <taxonomy> <title> <description> <file_path>")
        else:
            with open(parsed.args[3], 'r', encoding='utf-8') as f:
                content = f.read()
            entry_id = parsed.args[1].lower().replace(' ', '_')
            core.safe_add_entry({
                "id": entry_id,
                "title": parsed.args[1],
                "taxonomy_path": parsed.args[0],
                "description": parsed.args[2],
                "importance": 5,
                "dependencies": []
            }, content)
    elif parsed.cmd == "search":
        q = parsed.args[0] if parsed.args else ""
        results = core.search(query=q)
        for r in results:
            print(f"[{r['taxonomy_path']}] {r['title']} (v{r['version']}, Hash: {r['content_hash'][:8]})")
    elif parsed.cmd == "rollback":
        if len(parsed.args) < 1 or not parsed.version:
            print("Usage: rollback <entry_id> --version <target_version>")
        else:
            core.rollback(parsed.args[0], parsed.version)
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
