import os
import sys
import json
import shutil
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))
from manager_v2 import EternalCore

def test_e2ee_flow():
    print("=== Starting E2EE & Blind Mirror Test ===")
    
    # Paths
    root = Path(os.getcwd())
    master_dir = root / "test_master"
    mirror_dir = root / "test_mirror"
    receiver_dir = root / "test_receiver"
    pkg_path = root / "transfer.zip"
    mirror_pkg_path = root / "mirror_transfer.zip"
    
    # Cleanup
    for d in [master_dir, mirror_dir, receiver_dir]:
        if d.exists(): shutil.rmtree(d)
    if pkg_path.exists(): os.remove(pkg_path)
    if mirror_pkg_path.exists(): os.remove(mirror_pkg_path)

    # 1. Master Node Setup
    print("\n[1] Setting up Master Node...")
    EternalCore.init_repo(master_dir, role="master")
    
    # Inject Master Key
    config_path = master_dir / ".eternal" / "config.json"
    with open(config_path, 'r') as f: config = json.load(f)
    config['master_key'] = "secret_password_123"
    with open(config_path, 'w') as f: json.dump(config, f)
    
    # Initialize Core
    master_core = EternalCore(master_dir / ".eternal", master_key="secret_password_123")
    
    # Get Salt from Master to ensure Receiver can derive same key
    res = master_core.db.fetchone("SELECT value FROM repo_info WHERE key='crypto_salt'")
    master_salt = res['value'] if res else None
    print(f"    Master Salt: {master_salt}")

    # Store Encrypted Object
    print("    Storing encrypted object...")
    master_core.put("secret_doc", "This is top secret!", metadata={"encrypt": True, "compress": False})
    
    # Export
    print("    Exporting package...")
    master_core.export_package(pkg_path)
    
    # 2. Mirror Node Setup (Blind)
    print("\n[2] Setting up Blind Mirror Node...")
    EternalCore.init_repo(mirror_dir, role="mirror")
    
    # Ensure NO Master Key in config (default)
    
    # Initialize Core (No key)
    mirror_core = EternalCore(mirror_dir / ".eternal") # No master_key passed
    
    # Import
    print("    Importing package from Master...")
    mirror_core.import_package(pkg_path)
    
    # Try to Access (Should Fail)
    print("    Attempting to read secret (Expect Failure)...")
    try:
        content = mirror_core.get("secret_doc")
        # If get returns dict, check content
        if content and b"This is top secret!" in content['content']:
             print("    [FAIL] Mirror was able to decrypt the content!")
        else:
             print("    [SUCCESS] Mirror returned encrypted blob or failed.")
    except Exception as e:
        print(f"    [SUCCESS] Mirror failed to decrypt as expected: {e}")

    # Export from Mirror
    print("    Exporting package from Mirror...")
    mirror_core.export_package(mirror_pkg_path)

    # 3. Receiver Node Setup
    print("\n[3] Setting up Receiver Node (with Key)...")
    # Initialize with same salt as Master
    EternalCore.init_repo(receiver_dir, role="master", crypto_salt=master_salt)
    
    # Inject Same Master Key
    config_path = receiver_dir / ".eternal" / "config.json"
    with open(config_path, 'r') as f: config = json.load(f)
    config['master_key'] = "secret_password_123"
    with open(config_path, 'w') as f: json.dump(config, f)
    
    receiver_core = EternalCore(receiver_dir / ".eternal", master_key="secret_password_123")
    
    # Import from Mirror
    print("    Importing package from Mirror...")
    receiver_core.import_package(mirror_pkg_path)
    
    # Try to Access (Should Succeed)
    print("    Attempting to read secret...")
    try:
        res = receiver_core.get("secret_doc")
        content = res['content']
        if isinstance(content, bytes): content = content.decode()
        
        if content == "This is top secret!":
            print("    [SUCCESS] Receiver successfully decrypted the content.")
        else:
            print(f"    [FAIL] Content mismatch: {content}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"    [FAIL] Receiver failed to decrypt: {repr(e)}")

if __name__ == "__main__":
    test_e2ee_flow()
