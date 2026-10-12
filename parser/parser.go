package parser

import (
	"azure-firewall-elastic-shipper/model"
	"encoding/json"
	"log/slog"
)

func ParseNetworkRule(record json.RawMessage) model.LogEntityNetworkRule {
	var logEntity model.LogEntityNetworkRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return model.LogEntityNetworkRule{}
	}
	//jsonData, _ := json.Marshal(logEntity)
	//fmt.Println(string(jsonData))

	return logEntity
}

func ParseNatRule(record json.RawMessage) model.LogEntityNatRule {
	var logEntity model.LogEntityNatRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return model.LogEntityNatRule{}
	}
	//jsonData, _ := json.Marshal(logEntity)
	//fmt.Println(string(jsonData))

	return logEntity
}

func ParseApplicationRule(record json.RawMessage) model.LogEntityApplicationRule {
	var logEntity model.LogEntityApplicationRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return model.LogEntityApplicationRule{}
	}
	//jsonData, _ := json.Marshal(logEntity)
	//fmt.Println(string(jsonData))

	return logEntity
}
