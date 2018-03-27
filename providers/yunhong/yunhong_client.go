package yunhong

import (
	"github.com/rancher/rancher-auth-service/model"
	"gopkg.in/cas.v2"
)

const (
	gheAPI                = "/api/v3"
	githubAccessToken     = Name + "access_token"
	githubAPI             = "https://api.github.com"
	githubDefaultHostName = "https://github.com"
)

//YHClient implements a httpclient for github
type YHClient struct {
	casClient *cas.Client
	config     *model.YunhongConfig
}

