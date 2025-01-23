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

package kolog

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerScope("Kmesh_module")
)

func parseLogTime(line string) (time.Time, error) {
	re := regexp.MustCompile(`\[(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]`)
	match := re.FindStringSubmatch(line)
	if len(match) < 2 {
		return time.Time{}, fmt.Errorf("no time match found")
	}

	logTime, err := time.Parse("Mon Jan 2 15:04:05 2006", match[1])
	if err != nil {
		return time.Time{}, err
	}
	return logTime, nil
}

func KmeshModuleLog(stopCh <-chan struct{}) {
	go func() {
		cmd := exec.Command("dmesg", "-wT")

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Errorf("Error creating stdout pipe: %v", err)
			return
		}

		startTime := time.Now()
		if err := cmd.Start(); err != nil {
			log.Errorf("Error starting command: %v", err)
			return
		}

		scanner := bufio.NewScanner(stdout)
		for {
			select {
			case <-stopCh:
				if cmd.Process != nil {
					if err := cmd.Process.Kill(); err != nil {
						log.Errorf("Error killing process: %v", err)
					} else {
						if processState, err := cmd.Process.Wait(); err != nil {
							log.Errorf("Error waiting for process: %v, processState:%v", err, processState)
						}
					}
				}
				return
			default:
				if !scanner.Scan() {
					if err := scanner.Err(); err != nil {
						log.Errorf("Error reading from stdout: %v", err)
					}
					break
				}
				line := scanner.Text()

				if !strings.Contains(line, "Kmesh_module") {
					continue
				}
				logTime, err := parseLogTime(line)
				if err != nil {
					log.Errorf("Error parsing log time: %v", err)
					log.Info(line)
					continue
				}
				if logTime.After(startTime) {
					log.Info(line)
				}
			}
		}
	}()
}
