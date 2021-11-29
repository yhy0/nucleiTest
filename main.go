package main

import (
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"nucleiTest/scan"
)

func main() {
	// 下载配置文件及模板
	scan.Setup()

	targets := []string{
		"https://docs.hackerone.com/",
		"https://www.baidu.com/",
	}

	// 使用nuclei内置的输出流接收结果
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		// 转为 json
		result, err := json.Marshal(event.Matched)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("Got Result: %s\n", string(result))
	}

	for _, target := range targets{
		// 扫描
		scan.Nuclei(target, outputWriter)
	}

}
