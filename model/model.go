package model

type AzureClientSecret struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

type LogEntityNetworkRule struct {
	Category   string                `json:"category"`
	Time       string                `json:"time"`
	ResourceId string                `json:"resourceId"`
	Properties NetworkRuleProperties `json:"properties"`
}

type NetworkRuleProperties struct {
	Protocol            string `json:"Protocol"`
	SourceIp            string `json:"SourceIp"`
	SourcePort          int32  `json:"SourcePort"`
	DestinationIp       string `json:"DestinationIp"`
	DestinationPort     int32  `json:"DestinationPort"`
	Action              string `json:"Action"`
	Policy              string `json:"Policy"`
	RuleCollectionGroup string `json:"RuleCollectionGroup"`
	RuleCollection      string `json:"RuleCollection"`
	Rule                string `json:"Rule"`
	ActionReason        string `json:"ActionReason"`
}

type LogEntityNatRule struct {
	Category   string            `json:"category"`
	Time       string            `json:"time"`
	ResourceId string            `json:"resourceId"`
	Properties NatRuleProperties `json:"properties"`
}

type NatRuleProperties struct {
	Protocol            string `json:"Protocol"`
	SourceIp            string `json:"SourceIp"`
	SourcePort          int32  `json:"SourcePort"`
	DestinationIp       string `json:"DestinationIp"`
	DestinationPort     int32  `json:"DestinationPort"`
	TranslatedIp        string `json:"TranslatedIp"`
	TranslatedPort      int32  `json:"TranslatedPort"`
	Policy              string `json:"Policy"`
	RuleCollectionGroup string `json:"RuleCollectionGroup"`
	RuleCollection      string `json:"RuleCollection"`
	Rule                string `json:"Rule"`
}

type LogEntityApplicationRule struct {
	Category   string                    `json:"category"`
	Time       string                    `json:"time"`
	ResourceId string                    `json:"resourceId"`
	Properties ApplicationRuleProperties `json:"properties"`
}

type ApplicationRuleProperties struct {
	Protocol            string `json:"Protocol"`
	SourceIp            string `json:"SourceIp"`
	SourcePort          int32  `json:"SourcePort"`
	DestinationIp       string `json:"DestinationIp"`
	DestinationPort     int32  `json:"DestinationPort"`
	FQDN                string `json:"Fqdn"`
	RequestUri          string `json:"RequestUri"`
	Action              string `json:"Action"`
	RuleCollectionGroup string `json:"RuleCollectionGroup"`
	RuleCollection      string `json:"RuleCollection"`
	Rule                string `json:"Rule"`
}
