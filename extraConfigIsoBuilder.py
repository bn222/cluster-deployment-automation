from dpuVendor import detect_dpu
from isoBuilder import BootcIsoBuilder
import host
from logger import logger
from typing import Optional, cast
from concurrent.futures import Future
from clustersConfig import ClustersConfig, ExtraConfigArgs
import datetime


def ExtraConfigIsoBuilder(
    cc: ClustersConfig,
    cfg: ExtraConfigArgs,
    futures: dict[str, Future[Optional[host.Result]]],
) -> None:
    # Wait for all futures to complete
    [f.result() for (_, f) in futures.items()]

    lh = host.LocalHost()
    logger.info("Running config step to build DPU iso")

    # Required non-default parameters for BootcIsoBuilder
    required_params = [
        (cfg.organization_id, "organization_id"),
        (cfg.activation_key, "activation_key"),
        (cfg.image_mode_url, "image_mode_url"),
        (cfg.iso_builder_url, "iso_builder_url"),
    ]

    missing_fields = [name for (value, name) in required_params if value is None]
    if missing_fields:
        logger.error_and_exit(f"Error: Missing required configuration for DPU ISO build: " f"{', '.join(missing_fields)}. Please ensure these are specified in your configuration.")

    today_str = datetime.date.today().strftime("%Y%m%d")
    final_iso_name: str = cfg.final_iso_name or cc.install_iso or f"RHEL-DPU-CUSTOM-LATEST-{today_str}-aarch64.iso"
    # Safe because of required param check
    organization_id: str = cast(str, cfg.organization_id)
    activation_key: str = cast(str, cfg.activation_key)
    image_mode_url: str = cfg.image_mode_url
    iso_builder_url: str = cfg.iso_builder_url
    bootc_build_local: bool = cfg.bootc_build_local
    bootc_dir: str = cfg.bootc_dir
    iso_builder_auth_file: Optional[str] = cfg.iso_builder_auth_file

    # Optional bootc iso build params
    input_iso: Optional[str] = cfg.input_iso
    kickstart: Optional[str] = cfg.kickstart
    kernel_args: Optional[str] = cfg.iso_kargs
    remove_args: Optional[str] = cfg.remove_args

    if len(cc.masters) < 1:
        logger.error_and_exit("Error: At least one master is needed for the OS environment to match the DPU requirements")
    node = cc.masters[0]
    dpu_flavor = detect_dpu(node) if node.kind == "dpu" else "agnostic"
    if dpu_flavor == "ipu":
        extra_args = " ip=192.168.0.2:::255.255.255.0::enp0s1f0:off netroot=iscsi:192.168.0.1::::iqn.e2000:acc acpi=force"
        kernel_args = (kernel_args or "") + extra_args
        remove_args = "rd.live.check"
        grub_replacements = [
            "timeout=60|timeout=5",
        ]

    # Build the ISO
    BootcIsoBuilder(
        host=lh,
        name_of_final_iso=final_iso_name,
        secrets_path=cc.secrets_path,
        organization_id=organization_id,
        activation_key=activation_key,
        bootc_image_url=image_mode_url,
        image_builder_url=iso_builder_url,
        input_iso=input_iso,
        kickstart=kickstart,
        kernel_args=kernel_args,
        remove_args=remove_args,
        dpu_flavor=dpu_flavor,
        auth_file_path=iso_builder_auth_file,  # Use auth file from iso_builder config
        bootc_build_local=bootc_build_local,
        grub_replacements=grub_replacements,
        bootc_dir=bootc_dir,
    ).build()
