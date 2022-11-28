import host

def export(path):
  exports = "/etc/exports"
  with open(exports, "r") as f:
    contents = f.read()
  for e in contents:
    if e.split(" ")[0] == path:
      return
  contents += f"\n{path}"
  with open(exports, "w") as f:
    f.write(contents)
  lh = host.LocalHost()
  lh.run("systemctl enable nfs-server")
  lh.run("systemctl restart nfs-server")
