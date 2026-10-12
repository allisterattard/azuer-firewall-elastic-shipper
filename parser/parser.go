package parser

import (
	"azure-firewall-elastic-shipper/model"
	"encoding/json"
	"log"
)

func ParseNetworkRule(record json.RawMessage) {
	var logEntity model.LogEntityNetworkRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		log.Printf("Failed to parse log record JSON: %v", err)
		return
	}
	jsonData, _ := json.Marshal(logEntity)
	log.Printf("%s", string(jsonData))
}

func ParseNatRule(record json.RawMessage) {
	var logEntity model.LogEntityNatRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		log.Printf("Failed to parse log record JSON: %v", err)
		return
	}
	jsonData, _ := json.Marshal(logEntity)
	log.Printf("%s", string(jsonData))
}

func ParseApplicationRule(record json.RawMessage) {
	var logEntity model.LogEntityApplicationRule
	if err := json.Unmarshal(record, &logEntity); err != nil {
		log.Printf("Failed to parse log record JSON: %v", err)
		return
	}
	jsonData, _ := json.Marshal(logEntity)
	log.Printf("%s", string(jsonData))
}
