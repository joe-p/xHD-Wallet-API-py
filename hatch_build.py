import subprocess
import os
import shutil
import platform
from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # type: ignore

class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        project_root = self.root
        rust_dir = os.path.join(project_root, "rust-ed25519-bip32")
        package_dir = os.path.join(project_root, "src", "xhd_wallet_api_py")
        
        # Ensure package directory exists
        os.makedirs(package_dir, exist_ok=True)
       
        subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=project_root,
            check=True
        )

        # Run cargo build --release with external-api feature
        subprocess.run(
            ["cargo", "build", "--release", "--features", "external-api"],
            cwd=rust_dir,
            check=True
        )
        
        # Determine library extension based on platform
        system = platform.system()
        if system == "Darwin":
            lib_ext = ".dylib"
        elif system == "Linux":
            lib_ext = ".so"
        elif system == "Windows":
            lib_ext = ".dll"
        else:
            raise RuntimeError(f"Unsupported platform: {system}")
        
        # Copy the built library to the package directory
        src_lib = os.path.join(rust_dir, "target", "release", f"libed25519_bip32{lib_ext}")
        dst_lib = os.path.join(package_dir, f"libed25519_bip32{lib_ext}")
        
        if os.path.exists(src_lib):
            shutil.copy2(src_lib, dst_lib)
            print(f"Copied {src_lib} to {dst_lib}")
        else:
            raise RuntimeError(f"Built library not found at {src_lib}")
        
        # Add the library to the wheel
        build_data["force_include"][dst_lib] = f"xhd_wallet_api_py/libed25519_bip32{lib_ext}"
        
        return super().initialize(version, build_data)
