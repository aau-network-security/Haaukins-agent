// Copyright (c) 2018-2019 Aalborg University
// Use of this source code is governed by a GPLv3
// license that can be found in the LICENSE file.

package virtual

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"regexp"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// TODO comments and docs
type InstanceConfig struct {
	Image    string  `yaml:"image"`
	MemoryMB uint    `yaml:"memoryMB"`
	CPU      float64 `yaml:"cpu"`
}

const (
	stateRegex = `State:\s*(.*)`
	nicRegex   = "\\bNIC\\b"

	vboxBin             = "VBoxManage"
	vboxModVM           = "modifyvm"
	vboxStartVM         = "startvm"
	vboxCtrlVM          = "controlvm"
	vboxUnregisterVM    = "unregistervm"
	vboxShowVMInfo      = "showvminfo"
	NOAVAILABLEFRONTEND = "No available frontends found on your setup, please add at least one ova file !"
)

var FileTransferRoot string

func init() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

type VBoxErr struct {
	Action string
	Output []byte
}

func (err *VBoxErr) Error() string {
	return fmt.Sprintf("VBoxError [%s]: %s", err.Action, string(err.Output))
}

// type VmHandler interface {
// 	Instance
// 	Snapshot(string) error
// 	LinkedClone(context.Context, string, ...VMOpt) (VmHandler, error)
// }

// type VboxLibraryHandler interface {
// 	GetCopy(context.Context, InstanceConfig, ...VMOpt) (*Vm, error)
// 	IsAvailable(string) bool
// 	GetImagePath(string) string
// }

type VboxLibrary struct {
	M     sync.Mutex
	Pwd   string
	Known map[string]*Vm
	Locks map[string]*sync.Mutex
}

// VM information is stored in a struct
type Vm struct {
	Id      string
	Path    string
	Image   string
	opts    []VMOpt
	Running bool
}

func NewVMWithSum(path, image string, checksum string, vmOpts ...VMOpt) *Vm {
	return &Vm{
		Path:  path,
		Image: image,
		opts:  vmOpts,
		Id:    fmt.Sprintf("%s{%s}", image, checksum),
	}
}

// Creating VM
func (vm *Vm) Create(ctx context.Context) error {
	_, err := VBoxCmdContext(ctx, "import", vm.Path, "--vsys", "0", "--eula", "accept", "--vmname", vm.Id)
	if err != nil {
		return err
	}

	for _, opt := range vm.opts {
		if err := opt(ctx, vm); err != nil {
			return err
		}
	}

	return nil
}

// when Run is called, it calls Create function within it.
func (vm *Vm) Run(ctx context.Context) error {
	if err := vm.Create(ctx); err != nil {
		return err
	}

	return vm.Start(ctx)
}

func (vm *Vm) Start(ctx context.Context) error {
	_, err := VBoxCmdContext(ctx, vboxStartVM, vm.Id, "--type", "headless")
	if err != nil {
		return err
	}

	vm.Running = true

	log.Debug().
		Str("ID", vm.Id).
		Msg("Started VM")

	log.Debug().
		Str("ID", vm.Id).
		Msg("Setting resolution for VM")
	_, err = VBoxCmdContext(ctx, vboxCtrlVM, vm.Id, "setvideomodehint", "1920", "1080", "16")
	if err != nil {
		log.Error().Str("ID", vm.Id).Msgf("Error setting resolution, VM may require reset on after connecting: %s", err.Error())
	}

	return nil
}

func (vm *Vm) Stop() error {
	_, err := VBoxCmdContext(context.Background(), vboxCtrlVM, vm.Id, "poweroff")
	if err != nil {
		log.Error().Msgf("Error while shutting down VM %s", err)
		return err
	}

	vm.Running = false

	log.Debug().
		Str("ID", vm.Id).
		Msg("Stopped VM")

	return nil
}

// Will call savestate on vm
func (vm *Vm) Suspend(ctx context.Context) error {
	_, err := VBoxCmdContext(ctx, vboxCtrlVM, vm.Id, "savestate")
	if err != nil {
		log.Error().
			Str("ID", vm.Id).
			Msgf("Failed to suspend VM: %v", err)
		return err
	}

	log.Debug().
		Str("ID", vm.Id).
		Msgf("Suspended vm")

	return nil
}

func (vm *Vm) Close() error {
	_, err := vm.ensureStopped(nil)
	if err != nil {
		log.Warn().
			Str("ID", vm.Id).
			Msgf("Failed to stop VM: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = VBoxCmdContext(ctx, vboxUnregisterVM, vm.Id, "--delete")
	if err != nil {
		return err
	}

	log.Debug().
		Str("ID", vm.Id).
		Msg("Closed VM")

	return nil
}

type VMOpt func(context.Context, *Vm) error

func removeAllNICs(ctx context.Context, vm *Vm) error {
	result, err := VBoxCmdContext(ctx, vboxShowVMInfo, vm.Id)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(nicRegex)
	numberOfNICs := re.FindAll(result, -1)
	for i := 1; i <= len(numberOfNICs); i++ {
		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--nic"+strconv.Itoa(i), "none")
		if err != nil {
			return err
		}
	}
	return nil
}

func SetBridge(nic string) VMOpt {
	return func(ctx context.Context, vm *Vm) error {
		// Removes all NIC cards from importing VMs
		if err := removeAllNICs(ctx, vm); err != nil {
			return err
		}
		// enables specified NIC card in purpose
		_, err := VBoxCmdContext(ctx, vboxModVM, vm.Id, "--nic1", "bridged", "--bridgeadapter1", nic)
		if err != nil {
			return err
		}
		// allows promiscuous mode
		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--nicpromisc1", "allow-all")
		if err != nil {
			return err
		}

		return nil
	}
}

func SetLocalRDP(ip string, port uint) VMOpt {
	return func(ctx context.Context, vm *Vm) error {
		_, err := VBoxCmdContext(ctx, vboxModVM, vm.Id, "--vrde", "on")
		if err != nil {
			return err
		}

		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--vrdeproperty", fmt.Sprintf("TCP/Address=%s", ip))
		if err != nil {
			return err
		}

		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--vrdeproperty", fmt.Sprintf("TCP/Ports=%d", port))
		if err != nil {
			return err
		}

		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--vrdeauthtype", "null")
		if err != nil {
			return err
		}

		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--vram", "128")
		if err != nil {
			return err
		}

		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--clipboard", "bidirectional")
		if err != nil {
			return err
		}

		_, err = VBoxCmdContext(ctx, vboxModVM, vm.Id, "--vrdemulticon", "on")
		if err != nil {
			return err
		}

		return nil
	}
}

func SetCPU(cores uint) VMOpt {
	return func(ctx context.Context, vm *Vm) error {
		_, err := VBoxCmdContext(ctx, vboxModVM, vm.Id, "--cpus", fmt.Sprintf("%d", cores))
		return err
	}
}

func SetRAM(mb uint) VMOpt {
	return func(ctx context.Context, vm *Vm) error {
		_, err := VBoxCmdContext(ctx, vboxModVM, vm.Id, "--memory", fmt.Sprintf("%d", mb))
		return err
	}
}

func (vm *Vm) ensureStopped(ctx context.Context) (func(), error) {
	log.Debug().Msgf("vm: %v", vm)
	wasRunning := vm.Running
	if vm.Running {
		if err := vm.Stop(); err != nil {
			return nil, err
		}
	}

	return func() {
		if wasRunning {
			vm.Start(ctx)
		}
	}, nil
}
func (vm *Vm) Snapshot(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := VBoxCmdContext(ctx, "snapshot", vm.Id, "take", name)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vm) LinkedClone(ctx context.Context, snapshot string, vmOpts ...VMOpt) (*Vm, error) {
	newID := strings.Replace(uuid.New().String(), "-", "", -1)
	_, err := VBoxCmdContext(ctx, "clonevm", v.Id, "--snapshot", snapshot, "--options", "link", "--name", newID, "--register")
	if err != nil {
		return nil, err
	}

	vm := &Vm{
		Image: v.Image,
		Id:    newID,
	}
	for _, opt := range vmOpts {
		if err := opt(ctx, vm); err != nil {
			return nil, err
		}
	}

	return vm, nil
}

func (v *Vm) state() State {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw, err := VBoxCmdContext(ctx, vboxShowVMInfo, v.Id)
	if err != nil {
		return Error
	}

	r := regexp.MustCompile(stateRegex)
	matched := r.FindSubmatch(raw)
	if len(matched) == 0 {
		return Error
	}
	if strings.Contains(string(matched[0]), "running") {
		return Running
	}
	if strings.Contains(string(matched[0]), "saved") {
		return Suspended
	}

	return Stopped
}

func (v *Vm) Info() InstanceInfo {
	return InstanceInfo{
		Image: v.Image,
		Type:  "vbox",
		Id:    v.Id,
		State: v.state(),
	}
}

func NewLibrary(pwd string) *VboxLibrary {
	return &VboxLibrary{
		Pwd:   pwd,
		Known: make(map[string]*Vm),
		Locks: make(map[string]*sync.Mutex),
	}
}

func (lib *VboxLibrary) GetImagePath(file string) string {
	if !strings.HasPrefix(file, lib.Pwd) {
		file = filepath.Join(lib.Pwd, file)
	}

	if !strings.HasSuffix(file, ".ova") {
		file += ".ova"
	}

	return file
}

func (lib *VboxLibrary) GetCopy(ctx context.Context, conf InstanceConfig, vmOpts ...VMOpt) (*Vm, error) {
	path := lib.GetImagePath(conf.Image)

	lib.M.Lock()

	pathLock, ok := lib.Locks[path]
	if !ok {
		pathLock = &sync.Mutex{}
		lib.Locks[path] = pathLock
	}

	log.Debug().
		Str("path", path).
		Bool("first_time", ok == false).
		Msg("getting path lock")

	lib.M.Unlock()

	pathLock.Lock()
	defer pathLock.Unlock()

	vm, ok := lib.Known[path]
	if ok {
		return vm.LinkedClone(ctx, "origin", vmOpts...) // if ok==true then VM will be linked without the ram value which is exist on configuration file
		// vbox.SetRAM(conf.memoryMB) on addFrontend function in lab.go fixes the problem...
	}
	// if ok==false, then following codes will be run, in that case there will be no problem because at the end instance returns with specified VMOpts parameter.
	sum, err := checksumOfFile(path)
	if err != nil {
		return nil, err
	}

	n := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	vm, ok = VmExists(n, sum)
	if !ok {
		vm = NewVMWithSum(path, n, sum)
		if err := vm.Create(ctx); err != nil {
			return nil, err
		}

		err = vm.Snapshot("origin")
		if err != nil {
			return nil, err
		}
	}

	lib.M.Lock()
	lib.Known[path] = vm
	lib.M.Unlock()

	if conf.CPU != 0 {
		vmOpts = append(vmOpts, SetCPU(uint(math.Ceil(conf.CPU))))
	}

	if conf.MemoryMB != 0 {
		vmOpts = append(vmOpts, SetRAM(conf.MemoryMB))
	}

	instance, err := vm.LinkedClone(ctx, "origin", vmOpts...)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (lib *VboxLibrary) IsAvailable(file string) bool {
	path := lib.GetImagePath(file)
	if _, err := os.Stat(path); err == nil {
		return true
	}

	return false
}

func checksumOfFile(filepath string) (string, error) {
	hash := crc32.NewIEEE()

	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}

	checksum := hash.Sum(nil)
	return hex.EncodeToString(checksum), nil
}

func VmExists(image string, checksum string) (*Vm, bool) {
	name := fmt.Sprintf("%s{%s}", image, checksum)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := VBoxCmdContext(ctx, "list", "vms")
	if err != nil {
		return nil, false
	}

	if bytes.Contains(out, []byte("\""+name+"\"")) {
		return &Vm{
			Image: image,
			Id:    name,
		}, true
	}

	return nil, false
}

func VBoxCmdContext(ctx context.Context, cmd string, cmds ...string) ([]byte, error) {
	command := append([]string{cmd}, cmds...)

	c := exec.CommandContext(ctx, vboxBin, command...)
	out, err := c.CombinedOutput()
	if err != nil {
		return nil, &VBoxErr{
			Action: strings.Join(command, " "),
			Output: out,
		}
	}

	return out, nil
}

func CreateFileTransferRoot(path string) error {
	FileTransferRoot = path
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		//If path exists
		log.Info().Str("transfer-root", path).Msg("File transfer root already exists... Continuing.")
		return nil
	}
	log.Info().Str("transfer-root", path).Msg("File transfer root does not exists... Creating folder")
	err := os.MkdirAll(path, 0777)
	if err != nil {
		log.Warn().Msgf("Error creating file transfer root: %s", err)
		return err
	}
	err = os.Chmod(path, os.ModePerm)
	if err != nil {
		log.Warn().Msgf("Error setting folder perms on: %s error: %s", path, err)
		return err
	}
	log.Info().Msg("File transfer root succesfully created!")
	return nil
}

func CreateEventFolder(tag string) error {
	path := FileTransferRoot + "/" + tag
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		//If path exists
		log.Info().Str("event-root", path).Msg("Event root already exists... Continuing.")
		return nil
	}
	log.Info().Str("event-root", path).Msg("Event root does not exists... Creating folder")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		log.Warn().Msgf("Error creating event root: %s", err)
		return err
	}
	err = os.Chmod(path, os.ModePerm)
	if err != nil {
		log.Warn().Msgf("Error setting folder perms on: %s error: %s", path, err)
		return err
	}
	log.Info().Msg("Event root succesfully created!")
	return nil
}

func RemoveEventFolder(eventTag string) error {
	path := FileTransferRoot + "/" + eventTag
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		//If path exists
		log.Info().Str("Event-folder", path).Msg("Event-folder exists... Deleting.")
		err := os.RemoveAll(path)
		if err != nil {
			log.Warn().Msgf("Error deleting event folder: %s with error: %s", path, err)
			return err
		}
		return nil
	} else {
		log.Info().Str("Event-folder", path).Msg("Event-folder does not exists... Continueing")
		return nil
	}
}

func CreateUserFolder(teamId string, eventTag string) error {
	path := FileTransferRoot + "/" + eventTag + "/" + teamId
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		//If path exists
		log.Info().Str("User-folder", path).Msg("User-folder already exists... Continuing.")
		return nil
	}
	log.Info().Str("User-folder", path).Msg("User-folder does not exists... Creating folder")
	err := os.MkdirAll(path, 0777)
	if err != nil {
		log.Warn().Msgf("Error creating User-folder: %s", err)
		return err
	}
	err = os.Chmod(path, os.ModePerm)
	if err != nil {
		log.Warn().Msgf("Error setting folder perms on: %s error: %s", path, err)
		return err
	}
	log.Info().Msg("User-folder succesfully created!")
	return nil
}

func CreateFolderLink(vm string, eventTag string, teamId string) error {
	log.Debug().Msgf("Trying to link shared folder to vm: %s", vm)
	//todo Figure out a way to add the new folder and general setup of filetransfer folder and how to manage its content.
	_, err := VBoxCmdContext(context.Background(), "sharedfolder", "add", vm, "--name", "filetransfer", "-hostpath", FileTransferRoot+"/"+eventTag+"/"+teamId, "-transient", "-automount")
	if err != nil {
		log.Warn().Msgf("Error creating shared folder link: %s", err)
		return err
	}
	return nil
}
