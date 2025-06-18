# Iso Surgeon

**iso-surgeon** is a minimal Go-based tool used by CDA to build RHEL Bootc ISO images tailored for edge and embedded use cases.

It injects the following into a RHEL boot ISO:
- A kickstart file (`kickstart.ks`)
- GRUB kernel arguments
- A bootc container image (e.g., MicroShift)

This is required for workflows like DPU provisioning, where image-based deployments must include early container payloads.

---

## Usage (inside container)

> [!NOTE]
> For building from local images, it is required to specify the transport for the container image as the url prefix from the list below:
> "containers-storage:"
> "dir:"

> [!NOTE]
> The program assumes there's a mount for `workdir` so ensure this directory exist in the current directory!



```bash
sudo podman run --rm --privileged \
  --security-opt label=type:unconfined_t \
  --arch aarch64 \
  -v ${PWD}/workdir:/workdir \
  -v /var/lib/containers:/var/lib/containers \
  -v /run/containers/storage:/run/containers/storage \
  localhost/iso-surgeon \
  --bootc_image docker://quay.io/centos-bootc/centos-bootc:stream9
```

You can optionally provide:

* `--input_iso`: use an existing RHEL boot ISO
* `--kickstart`: custom kickstart file
* `--kernel_args`: GRUB arguments to inject
* `--output_iso`: destination path for the new ISO
* `--rhel_version`: the version of RHEL to generate if no input iso is given

---

## Build

```bash
# Build for aarch64
CGO_ENABLED=0 GOARCH=arm64 go build -o iso-surgeon main.go
```

Or build and run with Podman:

```bash
# Build container
sudo podman --security-opt label=type:unconfined_t build --platform linux/arm64 -t $ISO_BUILDER_URL .

# Push if needed
sudo podman push $ISO_BUILDER_URL
```

---

## Tools required (in container)

* `mkksiso`
* `skopeo`
* `losetup`

