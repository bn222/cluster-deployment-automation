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
	rhelVersion      string
	rootDir          string
}

func NewIsoBuilder() *IsoBuilder {
	return &IsoBuilder{
		kernelArgs: "",
		grubReplacements: []string{
			"timeout=60|timeout=5",
		},
		rhelVersion: "9.6",
		rootDir:     "/workdir",
	}
}

func main() {
	ib := NewIsoBuilder()
	rootCmd := &cobra.Command{
		Use:   "iso-builder",
		Short: "Build a customized RHEL Bootc ISO",
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
	rootCmd.Flags().StringVarP(&ib.rhelVersion, "rhel_version", "v", ib.rhelVersion, "RHEL version")

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

	if arch := strings.TrimSpace(runCmdOutput("uname", "-m")); arch != "aarch64" {
		return fmt.Errorf("must run on aarch64 (got %s)", arch)
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

	return exec.Command("skopeo", "copy",
		"--override-arch=arm64",
		ib.bootcImage,
		"oci:/tmp/container:latest").Run()
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
		versionBits := strings.Split(ib.rhelVersion, ".")
		if len(versionBits) != 2 {
			return fmt.Errorf("invalid RHEL version format: expected MAJOR.MINOR")
		}
		major := versionBits[0]
		minor := versionBits[1]
		downloadURL := fmt.Sprintf(
			"http://download.eng.bos.redhat.com/rhel-%s/nightly/RHEL-%s/latest-RHEL-%s.%s/compose/BaseOS/aarch64/iso/",
			major, major, major, minor)

		cmd := fmt.Sprintf(
			`curl -s %s | grep -oP 'href="\K[RHEL-]*[\d\.-]+aarch64-boot\.iso(?=")' | head -n1`,
			downloadURL)

		isoName := runCmdOutput("bash", "-c", cmd)
		ib.inputISO = strings.TrimSpace(isoName)
		fmt.Println(ib.inputISO)

		if ib.inputISO == "" {
			return fmt.Errorf("failed to extract ISO file name from %s", downloadURL)
		}

		if _, err := os.Stat(ib.inputISO); err != nil {
			runCmd("curl", "-O", downloadURL+ib.inputISO)
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
