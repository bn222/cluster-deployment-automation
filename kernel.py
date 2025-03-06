import host
from logger import logger
import time

KERNEL_RPMS = [
    "https://download.devel.redhat.com/brewroot/work/tasks/2286/66882286/kernel-5.14.0-570.idpf.IIC_500.el9_6.x86_64.rpm",
    "https://download.devel.redhat.com/brewroot/work/tasks/2286/66882286/kernel-core-5.14.0-570.idpf.IIC_500.el9_6.x86_64.rpm",
    "https://download.devel.redhat.com/brewroot/work/tasks/2286/66882286/kernel-modules-5.14.0-570.idpf.IIC_500.el9_6.x86_64.rpm",
    "https://download.devel.redhat.com/brewroot/work/tasks/2286/66882286/kernel-modules-core-5.14.0-570.idpf.IIC_500.el9_6.x86_64.rpm",
    "https://download.devel.redhat.com/brewroot/work/tasks/2286/66882286/kernel-modules-extra-5.14.0-570.idpf.IIC_500.el9_6.x86_64.rpm",
]


def ensure_IIC_500_kernel_is_installed(h: host.Host) -> None:
    h.ssh_connect("core")
    ret = h.run("uname -r")
    if "5.14.0-570.idpf.IIC_500.el9_6.x86_64" in ret.out:
        logger.info("5.14.0-570.idpf.IIC_500.el9_6.x86_64 kernel already installed, skipping")
        return

    logger.info(f"Installing 5.14.0-570.idpf.IIC_500.el9_6.x86_64 kernel on {h.hostname()}")

    wd = "working_dir"
    h.run(f"rm -rf {wd}")
    h.run(f"mkdir -p {wd}")
    logger.info(KERNEL_RPMS)

    for e in KERNEL_RPMS:
        fn = e.split("/")[-1]
        cmd = f"curl -k -L -o {wd}/{fn} {e}"
        h.run(cmd)

    cmd = f"sudo rpm-ostree override replace {wd}/*.rpm"
    logger.info(cmd)
    while True:
        ret = h.run(cmd)
        output = ret.out.strip().split("\n")
        if output and output[-1] == 'Run "systemctl reboot" to start a reboot':
            break
        else:
            logger.info(output)
            logger.info("Output was something unexpected")

    h.run("sudo systemctl reboot")
    time.sleep(10)
    h.ssh_connect("core")
    ret = h.run("uname -r")
    if "5.14.0-570.idpf.IIC_500.el9_6.x86_64" not in ret.out:
        logger.error_and_exit(f"Failed to install 5.14.0-570.idpf.IIC_500.el9_6.x86_64 kernel on host {h.hostname()}")
