package model

import "github.com/rancher/go-rancher/v2"

//YunhongConfig stores the github config read from JSON file
type YunhongConfig struct {
	client.Resource
	CasServerAddress      string `json:"casServerAddress"`
	CasServiceUrl         string `json:"casServiceUrl"`
	CasServiceId          string `json:"casServiceId"`
}