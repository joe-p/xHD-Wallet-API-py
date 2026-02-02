import subprocess
import os
from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # type: ignore

class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        # Get the project root directory from the build data
        # build_data contains the root directory of the project
        project_root = self.root
        rust_dir = os.path.join(project_root, "rust-ed25519-bip32")
       
        subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=project_root,
            check=True
        )

        # Run cargo build --release
        subprocess.run(
            ["cargo", "build", "--release"],
            cwd=rust_dir,
            check=True
        )
        
        return super().initialize(version, build_data)
