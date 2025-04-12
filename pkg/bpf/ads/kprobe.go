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

package ads

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/constants"
)

func (kp *BpfKprobe) NewBpf(cfg *options.BpfConfig) error {
	kp.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh/map/"
	kp.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh/kprobe/"
	kp.Info.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(kp.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(kp.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (kp *BpfKprobe) loadKmeshKprobeObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = kp.Info.MapPath
	spec, err = loadKmeshKprobe()
	if err != nil || spec == nil {
		return nil, err
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&kp.KmeshKmeshKprobeObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}
func (kp *BpfKprobe) Load() error {
	/* load kmesh sockops main bpf prog */
	_, err := kp.loadKmeshKprobeObjects()
	if err != nil {
		return err
	}
	return nil
}

func (kp *BpfKprobe) Attach() error {
	var err error

	// pin bpf_link
	sendProgPinPath := filepath.Join(kp.Info.BpfFsPath, constants.Prog_link)
	recvProgPinPath := filepath.Join(kp.Info.BpfFsPath, constants.Prog_link)
	if restart.GetStartType() == restart.Restart {
		LinkSend, err := link.LoadPinnedLink(sendProgPinPath, &ebpf.LoadPinOptions{})
		if err != nil {
			return err
		}
		if err := LinkSend.Update(kp.KmeshKmeshKprobeObjects.BpfTcpSendmsg); err != nil {
			return fmt.Errorf("updating link %s failed: %w", sendProgPinPath, err)
		}

		LinkRecv, err := link.LoadPinnedLink(recvProgPinPath, &ebpf.LoadPinOptions{})
		if err != nil {
			return err
		}
		if err := LinkRecv.Update(kp.KmeshKmeshKprobeObjects.BpfTcpRecvmsg); err != nil {
			return fmt.Errorf("updating link %s failed: %w", recvProgPinPath, err)
		}

	} else {
		kp.LinkSend, err = link.Kprobe("tcp_sendmsg", kp.KmeshKmeshKprobeObjects.BpfTcpSendmsg, nil)
		if err != nil {
			log.Printf("tcp_sendmsg failed:%v", err)
			return err
		}

		kp.LinkRecv, err = link.Kprobe("tcp_recvmsg", kp.KmeshKmeshKprobeObjects.BpfTcpRecvmsg, nil)
		if err != nil {
			log.Printf("tcp_recvmsg  failed:%v", err)
			return err
		}

		if err = kp.LinkSend.Pin(sendProgPinPath); err != nil {
			return err
		}

		if err = kp.LinkRecv.Pin(recvProgPinPath); err != nil {
			return err
		}
	}
	return nil
}

func (kp *BpfKprobe) Detach() error {
	var value reflect.Value

	if err := kp.KmeshKmeshKprobeObjects.Close(); err != nil {
		return err
	}

	value = reflect.ValueOf(kp.KmeshKmeshKprobeObjects.KmeshKmeshKprobePrograms)
	if err := utils.UnpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(kp.KmeshKmeshKprobeObjects.KmeshKmeshKprobeMaps)
	if err := utils.UnpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(kp.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if kp.LinkRecv != nil {
		return kp.LinkRecv.Close()
	}
	if kp.LinkSend != nil {
		return kp.LinkSend.Close()
	}
	return nil
}
