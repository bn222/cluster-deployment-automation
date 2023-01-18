import os
import sys
import json
from git import Repo
import shutil
import host


def ensure_fcos_exists(dst="/root/iso/fedora-coreos.iso"):
  print("ensuring that fcos exists")
  if os.path.exists(dst):
    print(f"fcos found at {dst}, not rebuilding it")
  else:
    print(f"fcos not found at {dst}, building it now")
    builder = CoreosBuilder("/tmp/build")
    builder.build(dst)


class CoreosBuilder():
  def __init__(self, working_dir):
    self._workdir = working_dir

  def build(self, dst):
    fcos_dir = os.path.join(self._workdir, "fcos")
    lh = host.LocalHost()

    self._clone_if_not_exists("https://github.com/coreos/coreos-assembler.git")
    config_dir = self._clone_if_not_exists("https://github.com/coreos/fedora-coreos-config")

    contents = "packages:\n  - kernel-modules-extra\n"
    custom_yaml = os.path.join(config_dir, 'manifests/custom.yaml')
    print(f"writing {custom_yaml}")
    with open(custom_yaml, 'w') as outfile:
      outfile.write(contents)

    base_cfg = os.path.join(config_dir, "manifests/fedora-coreos-base.yaml")
    with open(base_cfg, 'r') as f:
      contents = f.read()

    new_str = "\n  - shared-el9.yaml\n  - custom.yaml\n"
    if new_str not in contents:
      contents = contents.replace("\n  - shared-el9.yaml\n", new_str)


    print(os.getcwd())
    manifest_lock = os.path.join(config_dir, "manifest-lock.x86_64.json")
    with open(manifest_lock) as f:
        j = json.load(f)
        j["packages"]["kernel-modules-extra"] = j["packages"]["kernel"]

    with open(manifest_lock, "w") as f:
        f.write(json.dumps(j, indent=4, sort_keys=True))

    with open(base_cfg, "w") as f:
      f.write(contents)

    print(f"Clearing dir {fcos_dir}")
    if os.path.exists(fcos_dir):
      shutil.rmtree(fcos_dir)
    os.makedirs(fcos_dir)
    os.chdir(fcos_dir)

    cmd = f"""
    podman run --rm -ti --security-opt label=disable --privileged             \
               --uidmap=1000:0:1 --uidmap=0:1:1000 --uidmap 1001:1001:64536   \
               -v {fcos_dir}:/srv/ --device /dev/kvm --device /dev/fuse       \
               --tmpfs /tmp -v /var/tmp:/var/tmp --name cosa                  \
               -v {config_dir}:/git:ro   \
               quay.io/coreos-assembler/coreos-assembler:latest
    """

    print("running commands locally")
    print(lh.run(cmd + " init /git"))
    print(lh.run(cmd + " fetch"))
    print(lh.run(cmd + " build"))
    print(lh.run(cmd + " buildextend-metal"))
    print(lh.run(cmd + " buildextend-metal4k"))
    print(lh.run(cmd + " buildextend-live"))

    embed_src = self._find_iso(fcos_dir)
    if embed_src is None:
      print("Couldn't find iso")
      sys.exit(-1)
    ign = embed_src.replace(".iso", "-embed.ign")

    with open(ign, "w") as f:
      f.write(self.create_ignition())

    if os.path.exists(dst):
      os.remove(dst)

    cmd = f"coreos-installer iso ignition embed -i {ign} -o {dst} {embed_src}"
    print(cmd)
    print(lh.run(cmd))
    print(lh.run(f"chmod a+rw {dst}"))

  def _find_iso(self, fcos_dir):
    for root, _, files in os.walk(fcos_dir, topdown=False):
      for name in files:
        if name.endswith(".iso"):
          return os.path.join(root, name)

  def _clone_if_not_exists(self, url):
    dest = url.split("/")[-1]
    if dest.endswith(".git"):
      dest = dest[:-4]

    repo_dir = os.path.join(self._workdir, dest)
    if os.path.exists(repo_dir):
      print(f"Repo exists at {repo_dir}, not touching it")
    else:
      print(f"Cloning repo to {repo_dir}")
      Repo.clone_from(url, repo_dir)
    return repo_dir

  def create_ignition(self, public_key_file = "/root/.ssh/id_rsa.pub"):
    with open(public_key_file, 'r') as f:
        key = " ".join(f.read().split(" ")[:-1])
    ign = {}

    ign["ignition"] = {"version" : "3.3.0"}
    ign["passwd"] = {"users" : [{"name" : "core", "sshAuthorizedKeys" : [key]}]}
    return json.dumps(ign)


def main():
  builder = CoreosBuilder("/tmp/build")
  destination = "/root/iso/fedora-coreos.iso"
  builder.build(destination)


if __name__ == "__main__":
  main()
