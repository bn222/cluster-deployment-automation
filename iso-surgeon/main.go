package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

type IsoBuilder struct {
	inputISO         string
	outputISO        string
	kickstartFile    string
	bootcImage       string
	kernelArgs       string
	removeGrubArgs   string
	grubReplacements []string
	streamVersion    string
	architecture     string
	rootDir          string
}

func NewIsoBuilder() *IsoBuilder {
	return &IsoBuilder{
		kernelArgs: "",
		grubReplacements: []string{
			"timeout=60|timeout=5",
		},
		streamVersion: "9",
		architecture:  "aarch64", // Default, can be overridden via flag
		rootDir:       "/workdir",
	}
}

func main() {
	ib := NewIsoBuilder()
	rootCmd := &cobra.Command{
		Use:   "iso-builder",
		Short: "Build a customized CentOS Stream Bootc ISO",
		Run: func(cmd *cobra.Command, args []string) {
			if err := ib.run(); err != nil {
				log.Fatalf("Error: %v", err)
			}
		},
	}

	rootCmd.Flags().StringVarP(&ib.inputISO, "input_iso", "i", "", "Path to input ISO")
	rootCmd.Flags().StringVarP(&ib.outputISO, "output_iso", "o", "output.iso", "Path to output ISO")
	rootCmd.Flags().StringVarP(&ib.kickstartFile, "kickstart", "k", "", "Path to kickstart file")
	rootCmd.Flags().StringVarP(&ib.bootcImage, "bootc_image", "u", "", "Bootc image URL or directory")
	rootCmd.Flags().StringVarP(&ib.kernelArgs, "kernel_args", "a", ib.kernelArgs, "Kernel arguments")
	rootCmd.Flags().StringVarP(&ib.removeGrubArgs, "remove_args", "r", "", "Grub arguments to remove")
	rootCmd.Flags().StringSliceVarP(&ib.grubReplacements, "grub_replace", "R", ib.grubReplacements, "GRUB replacements in format 'old_text|new_text' (splits on pipe)")
	rootCmd.Flags().StringVarP(&ib.streamVersion, "stream_version", "v", ib.streamVersion, "CentOS Stream version (major version, e.g., '9')")
	rootCmd.Flags().StringVarP(&ib.architecture, "architecture", "A", ib.architecture, "Architecture (e.g., aarch64, x86_64)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func (ib *IsoBuilder) run() error {
	for _, command := range []string{"mkksiso", "losetup", "skopeo"} {
		checkCommand(command)
	}

	if err := os.Chdir(ib.rootDir); err != nil {
		return fmt.Errorf("could not change to %s with error: %s", ib.rootDir, err)
	}

	if err := ensureLoopSupport(); err != nil {
		return fmt.Errorf("loop support failed: %s", err)
	}

	// Detect architecture from container image if provided
	if err := ib.detectArchitectureFromContainer(); err != nil {
		log.Printf("Warning: Could not detect architecture from container image: %v", err)
	}

	if _, err := os.Stat(ib.outputISO); err == nil {
		return fmt.Errorf("output ISO %s already exists", ib.outputISO)
	}

	fmt.Println("Fetching ISO...")
	imgErrCh := AsyncErr(ib.prepareContainerImage)
	isoErrCh := AsyncErr(ib.prepareInputIso)

	var imgDone, isoDone bool

	for !imgDone || !isoDone {
		select {
		case err := <-imgErrCh:
			imgDone = true
			if err != nil {
				return fmt.Errorf("container image preparation failed: %w", err)
			}
			fmt.Println("Done preparing container image!")

		case err := <-isoErrCh:
			isoDone = true
			if err != nil {
				return fmt.Errorf("ISO preparation failed: %w", err)
			}
			fmt.Println("Done fetching ISO!")
		}
	}

	if err := ib.prepareKickstart(); err != nil {
		return err
	}

	ib.outputISO = path.Join("/workdir", ib.outputISO)
	ib.inputISO = path.Join("/workdir", ib.inputISO)

	fmt.Println("Generating ISO...")
	args := []string{}
	if ib.kickstartFile != "" {
		args = append(args, "--ks", ib.kickstartFile)
	}
	args = append(args, "-a", "/tmp/container")
	if ib.kernelArgs != "" {
		args = append(args, "-c", ib.kernelArgs)
	}
	if ib.removeGrubArgs != "" {
		args = append(args, "-r", ib.removeGrubArgs)
	}
	// Add GRUB replacements
	for _, replacement := range ib.grubReplacements {
		if replacement != "" {
			log.Printf("DEBUG: Processing GRUB replacement: '%s'", replacement)
			parts := strings.Split(replacement, "|")
			log.Printf("DEBUG: Split into %d parts: %v", len(parts), parts)
			if len(parts) == 2 {
				log.Printf("DEBUG: Adding -R '%s' '%s'", parts[0], parts[1])
				args = append(args, "-R", parts[0], parts[1])
			} else {
				log.Printf("Skipping invalid GRUB replacement: %s", replacement)
			}
		}
	}
	args = append(args, ib.inputISO, ib.outputISO)
	log.Printf("DEBUG: Final mkksiso command args: %v", args)
	log.Printf("DEBUG: Full command will be: mkksiso %s", strings.Join(args, " "))
	runCmd("mkksiso", args...)
	fmt.Println("Done.")
	return nil
}

func checkCommand(name string) {
	_, err := exec.LookPath(name)
	if err != nil {
		log.Fatalf("Required command %s not found in PATH", name)
	}
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Command failed: %s %v", name, args)
	}
}

func runCmdOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		log.Fatalf("Command failed: %s %v", name, args)
	}
	return string(out)
}

func ensureLoopSupport() error {
	if _, err := os.Stat("/dev/loop-control"); os.IsNotExist(err) {
		return fmt.Errorf("/dev/loop-control missing. Are you in a privileged container?")
	}
	return nil
}

func (ib *IsoBuilder) prepareKickstart() error {
	if ib.kickstartFile == "" {
		log.Println("No kickstart provided. Skipping kickstart injection.")
		return nil
	}
	ib.kickstartFile = path.Join("/workdir", ib.kickstartFile)
	return nil
}

func (ib *IsoBuilder) prepareContainerImage() error {
	fmt.Println("Saving Bootc image to /tmp/container")
	runCmd("rm", "-rf", "/tmp/container")

	if !hasKnownTransport(ib.bootcImage) {
		log.Printf("No known transport prefix on image %s, assuming docker://", ib.bootcImage)
		ib.bootcImage = "docker://" + ib.bootcImage
	}

	// Map architecture names for skopeo
	arch := ib.architecture
	if arch == "x86_64" {
		arch = "amd64" // skopeo uses amd64 for x86_64
	}

	return exec.Command("skopeo", "copy",
		"--override-arch="+arch,
		ib.bootcImage,
		"oci:/tmp/container:latest").Run()
}

func (ib *IsoBuilder) detectArchitectureFromContainer() error {
	if ib.bootcImage == "" {
		// No container image provided, keep default architecture
		return nil
	}

	if !hasKnownTransport(ib.bootcImage) {
		log.Printf("No known transport prefix on image %s, assuming docker://", ib.bootcImage)
		ib.bootcImage = "docker://" + ib.bootcImage
	}

	// Use skopeo to inspect the container image and get its architecture
	cmd := exec.Command("skopeo", "inspect", ib.bootcImage)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Warning: Could not inspect container image for architecture: %v", err)
		return nil // Don't fail, just use default architecture
	}

	// Simple parsing to extract architecture from JSON output
	// Look for "architecture":"aarch64" or similar
	outputStr := string(output)
	if strings.Contains(outputStr, `"architecture":"aarch64"`) {
		ib.architecture = "aarch64"
		log.Printf("Detected architecture from container: %s", ib.architecture)
	} else if strings.Contains(outputStr, `"architecture":"amd64"`) {
		ib.architecture = "x86_64" // CentOS Stream uses x86_64 naming
		log.Printf("Detected architecture from container: %s", ib.architecture)
	} else if strings.Contains(outputStr, `"architecture":"x86_64"`) {
		ib.architecture = "x86_64"
		log.Printf("Detected architecture from container: %s", ib.architecture)
	}
	// If no recognized architecture found, keep the default

	return nil
}

var knownTransports = []string{
	"docker://",
	"containers-storage:",
	"oci:",
	"dir:",
	"docker-archive:",
	"oci-archive:",
	"docker-daemon:",
}

func hasKnownTransport(ref string) bool {
	for _, t := range knownTransports {
		if strings.HasPrefix(ref, t) {
			return true
		}
	}
	return false
}

func (ib *IsoBuilder) prepareInputIso() error {
	if ib.inputISO == "" {
		// Validate supported architecture
		if ib.architecture != "aarch64" && ib.architecture != "x86_64" {
			return fmt.Errorf("unsupported architecture: %s (supported: aarch64, x86_64)", ib.architecture)
		}

		// For CentOS Stream, we use a simpler versioning scheme (just major version)
		major := ib.streamVersion

		// Construct the CentOS Stream mirror URL
		downloadURL := fmt.Sprintf(
			"https://mirror.stream.centos.org/%s-stream/BaseOS/%s/iso/",
			major, ib.architecture)

		// For CentOS Stream, we can directly construct the ISO name
		// Format: CentOS-Stream-{major}-latest-{arch}-boot.iso
		isoName := fmt.Sprintf("CentOS-Stream-%s-latest-%s-boot.iso", major, ib.architecture)
		ib.inputISO = isoName
		fmt.Printf("Using CentOS Stream ISO: %s\n", ib.inputISO)

		// Check if ISO already exists locally
		if _, err := os.Stat(ib.inputISO); err != nil {
			fmt.Printf("Downloading ISO from: %s\n", downloadURL+ib.inputISO)
			runCmd("curl", "-O", downloadURL+ib.inputISO)
		} else {
			fmt.Printf("ISO already exists locally: %s\n", ib.inputISO)
		}
	}
	return nil
}

func AsyncErr(fn func() error) <-chan error {
	ch := make(chan error, 1)
	go func() {
		ch <- fn()
	}()
	return ch
}
