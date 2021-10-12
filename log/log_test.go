/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"testing"
)

func TestSugarLogger(_ *testing.T) {
	config := LogConfig{
		Module:   "[JS]",
		LogPath:  "/tmp/js.log",
		LogLevel: LEVEL_DEBUG,
		//MaxSize:      100,
		//MaxBackups:   200,
		MaxAge: 300,
		//Compress:     true,
		JsonFormat:   false,
		ShowLine:     true,
		LogInConsole: true,
	}

	logger, _ := InitSugarLogger(&config)
	logger.Info("this is info msg")
	logger.Debugf("hello %s", "chainmaker")
}
