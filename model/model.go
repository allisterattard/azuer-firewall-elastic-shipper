package model

type AzureClientSecret struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

type LogEntityNetworkRule struct {
	Category   string                `json:"category"`
	Time       string                `json:"time"`
	Timestamp  string                `json:"@timestamp"`
	ResourceId string                `json:"resourceId"`
	Properties NetworkRuleProperties `json:"properties"`
}

type NetworkRuleProperties struct {
	Protocol            string `json:"protocol"`
	SourceIp            string `json:"sourceIP"`
	SourcePort          int32  `json:"sourcePort"`
	DestinationIp       string `json:"destinationIP"`
	DestinationPort     int32  `json:"destinationPort"`
	Action              string `json:"action"`
	Policy              string `json:"policy"`
	RuleCollectionGroup string `json:"ruleCollectionGroup"`
	RuleCollection      string `json:"ruleCollection"`
	Rule                string `json:"rule"`
	ActionReason        string `json:"actionReason"`
}

type LogEntityNatRule struct {
	Category   string            `json:"category"`
	Time       string            `json:"time"`
	Timestamp  string            `json:"@timestamp"`
	ResourceId string            `json:"resourceId"`
	Properties NatRuleProperties `json:"properties"`
}

type NatRuleProperties struct {
	Protocol            string `json:"protocol"`
	SourceIp            string `json:"sourceIP"`
	SourcePort          int32  `json:"sourcePort"`
	DestinationIp       string `json:"destinationIP"`
	DestinationPort     int32  `json:"destinationPort"`
	TranslatedIp        string `json:"translatedIP"`
	TranslatedPort      int32  `json:"translatedPort"`
	Policy              string `json:"policy"`
	RuleCollectionGroup string `json:"ruleCollectionGroup"`
	RuleCollection      string `json:"ruleCollection"`
	Rule                string `json:"rule"`
}

type LogEntityApplicationRule struct {
	Category   string                    `json:"category"`
	Time       string                    `json:"time"`
	Timestamp  string                    `json:"@timestamp"`
	ResourceId string                    `json:"resourceId"`
	Properties ApplicationRuleProperties `json:"properties"`
}

type ApplicationRuleProperties struct {
	Protocol            string `json:"protocol"`
	SourceIp            string `json:"sourceIP"`
	SourcePort          int32  `json:"sourcePort"`
	DestinationIp       string `json:"destinationIP"`
	DestinationPort     int32  `json:"destinationPort"`
	FQDN                string `json:"fqdn"`
	RequestUri          string `json:"requestUri"`
	Action              string `json:"action"`
	RuleCollectionGroup string `json:"ruleCollectionGroup"`
	RuleCollection      string `json:"ruleCollection"`
	Rule                string `json:"rule"`
}
