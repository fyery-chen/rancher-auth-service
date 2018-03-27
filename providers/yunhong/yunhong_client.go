package yunhong

import (
	"github.com/rancher/rancher-auth-service/model"
)

//YHClient implements a httpclient for github
type YHClient struct {
	casClient  *Client
	config     *model.YunhongConfig
}

