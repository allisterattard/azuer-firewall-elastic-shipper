package parser

import (
	"azure-firewall-elastic-shipper/model"
	"encoding/json"
	"log/slog"
)

func ParseNetworkRule(record json.RawMessage) (model.LogEntityNetworkRule, error) {
	var logEntity model.LogEntityNetworkRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return model.LogEntityNetworkRule{}, err
	}

	logEntity.Timestamp = logEntity.Time

	return logEntity, nil
}

func ParseNatRule(record json.RawMessage) (model.LogEntityNatRule, error) {
	var logEntity model.LogEntityNatRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return model.LogEntityNatRule{}, err
	}

	logEntity.Timestamp = logEntity.Time

	return logEntity, nil
}

func ParseApplicationRule(record json.RawMessage) (model.LogEntityApplicationRule, error) {
	var logEntity model.LogEntityApplicationRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err, "raw_record", string(record))
		return model.LogEntityApplicationRule{}, err
	}

	logEntity.Timestamp = logEntity.Time

	return logEntity, nil
}
