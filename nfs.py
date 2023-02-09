import host

"""
NFS is needed in many cases to network mount the folder that contains
ISO files such that Red Fish Virtual Media managers can load the image.
"""
def export(path):
    exports = "/etc/exports"
    with open(exports, "r") as f:
        contents = f.read()
    for e in contents:
        if path in e:
            return
    contents += f"\n{path}"
    with open(exports, "w") as f:
        f.write(contents)
    lh = host.LocalHost()
    lh.run("systemctl enable nfs-server")
    lh.run("systemctl restart nfs-server")
