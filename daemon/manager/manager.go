/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package manager: kmesh daemon manager
package manager

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"lec-bit/kmesh/daemon/manager/uninstall"
	"lec-bit/kmesh/daemon/options"
	"lec-bit/kmesh/pkg/bpf"
	"lec-bit/kmesh/pkg/bpf/restart"
	"lec-bit/kmesh/pkg/cni"
	"lec-bit/kmesh/pkg/controller"
	"lec-bit/kmesh/pkg/logger"
	"lec-bit/kmesh/pkg/status"
)

const (
	pkgSubsys = "manager"
)

var log = logger.NewLoggerScope(pkgSubsys)

func NewCommand() *cobra.Command {
	configs := options.NewBootstrapConfigs()
	cmd := &cobra.Command{
		Use:          "kmesh-daemon",
		Short:        "Start kmesh daemon",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			printFlags(cmd.Flags())
			if err := configs.ParseConfigs(); err != nil {
				return err
			}
			return Execute(configs)
		},
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	addFlags(cmd, configs)

	// add sub commands
	cmd.AddCommand(uninstall.NewCmd())

	return cmd
}

// Execute start daemon manager process
func Execute(configs *options.BootstrapConfigs) error {
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Warn("rlimit.RemoveMemlock failed")
	}

	bpfLoader := bpf.NewBpfLoader(configs.BpfConfig)
	// there could be a case that bpf loader partially start failed, we still need to stop it, otherwise it cannot recover
	// https://github.com/lec-bit/kmesh/issues/951
	defer bpfLoader.Stop()
	if err := bpfLoader.Start(); err != nil {
		return err
	}
	log.Info("bpf loader start successfully")

	stopCh := make(chan struct{})
	defer close(stopCh)

	c := controller.NewController(configs, bpfLoader.GetBpfWorkload(), configs.BpfConfig.BpfFsPath, configs.BpfConfig.EnableBpfLog, configs.BpfConfig.EnableAccesslog)
	if err := c.Start(stopCh); err != nil {
		return err
	}
	log.Info("controller start successfully")
	defer c.Stop()

	statusServer := status.NewServer(c.GetXdsClient(), configs, bpfLoader.GetBpfLogLevel())
	statusServer.StartServer()
	defer func() {
		_ = statusServer.StopServer()
	}()

	cniInstaller := cni.NewInstaller(configs.BpfConfig.Mode,
		configs.CniConfig.CniMountNetEtcDIR, configs.CniConfig.CniConfigName, configs.CniConfig.CniConfigChained, configs.CniConfig.ServiceAccountPath)
	if err := cniInstaller.Start(); err != nil {
		return err
	}
	defer cniInstaller.Stop()
	log.Info("start cni successfully")

	setupSignalHandler()
	// set exit type, which can be used by bpf loader to decide whether to cleanup bpf prog
	restart.SetExitType(restart.InferNextStartType())
	return nil
}

func setupSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGABRT, syscall.SIGTSTP)

	<-ch
	log.Warn("exiting...")
}

// printFlags print flags
func printFlags(flags *pflag.FlagSet) {
	flags.VisitAll(func(flag *pflag.Flag) {
		log.Infof("FLAG: --%s=%q", flag.Name, flag.Value)
	})
}

func addFlags(cmd *cobra.Command, config *options.BootstrapConfigs) {
	config.AttachFlags(cmd)
	cmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
}
