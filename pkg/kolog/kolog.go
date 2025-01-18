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
	"sync"
	"time"

	"istio.io/pkg/log"
)

// parseLogTime 解析日志行中的时间戳
func parseLogTime(line string) (time.Time, error) {
	// 使用正则表达式匹配时间戳
	re := regexp.MustCompile(`\[(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]`)
	match := re.FindStringSubmatch(line)
	if len(match) < 2 {
		return time.Time{}, fmt.Errorf("no time match found")
	}
	// 解析时间字符串
	logTime, err := time.Parse("Mon Jan 2 15:04:05 2006", match[1])
	if err != nil {
		return time.Time{}, err
	}
	return logTime, nil
}

func KmeshModuleLog(wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		// 执行dmesg命令
		cmd := exec.Command("dmesg", "-wT")
		// 获取命令的标准输出
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Errorf("Error creating stdout pipe:", err)
			return
		}

		// 记录当前时间
		startTime := time.Now()
		// 启动命令
		if err := cmd.Start(); err != nil {
			log.Errorf("Error starting command:", err)
			return
		}
		// 使用bufio.Scanner读取输出
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			// 筛选以Kmesh_module开头的行
			if !strings.Contains(line, "Kmesh_module") {
				continue
			}
			logTime, err := parseLogTime(line)
			if err != nil {
				log.Errorf("Error parsing log time:", err)
				log.Info(line)
				continue
			}
			// 如果日志时间晚于当前进程启动时间，则打印
			if logTime.After(startTime) {
				log.Info(line)
			}
		}
		// 等待命令结束
		if err := cmd.Wait(); err != nil {
			fmt.Println("Error waiting for command to finish:", err)
		}
	}()

}
