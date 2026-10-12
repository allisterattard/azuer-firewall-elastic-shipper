package parser

import (
	"azure-firewall-elastic-shipper/model"
	"encoding/json"
	"fmt"
	"log/slog"
)

func ParseNetworkRule(record json.RawMessage) {
	var logEntity model.LogEntityNetworkRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return
	}
	jsonData, _ := json.Marshal(logEntity)
	fmt.Println(string(jsonData))
}

func ParseNatRule(record json.RawMessage) {
	var logEntity model.LogEntityNatRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return
	}
	jsonData, _ := json.Marshal(logEntity)
	fmt.Println(string(jsonData))
}

func ParseApplicationRule(record json.RawMessage) {
	var logEntity model.LogEntityApplicationRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return
	}
	jsonData, _ := json.Marshal(logEntity)
	fmt.Println(string(jsonData))
}
