package yunhong

import (
	"github.com/rancher/go-rancher/v2"
	"strconv"
)

const (
	userAdmin  = "admin"
	userNormal = "user"
)

//Account defines properties an account on github has
type UserAccount struct {
	Data	[]*UserDetailInfo	`json:"data"`
}

type UserDetailInfo struct {
	Id         		string `json:"id"`
	Name       		string `json:"name"`
	State      		int    `json:"state"`
	UserOnline 		int    `json:"userOnline"`
	RoleIds    		string `json:"roleIds"`
	RoleNames       string `json:"roleNames"`
	SystemIds  		string `json:"systemIds"`
	StateText  		string `json:"stateText"`
	UserType   	   	int    `json:"userType"`
	SystemRoleName 	string `json:"systemRoleName"`
}

func (a *UserDetailInfo) toIdentity(externalIDType string, identity *client.Identity, user bool) {
	identity.ExternalId = a.Id + strconv.Itoa(a.UserType)
	identity.Resource.Id = externalIDType + ":" + a.Id + strconv.Itoa(a.UserType)
	identity.ExternalIdType = externalIDType
	if a.Name != "" {
		identity.Name = a.Name
	} else {
		identity.Name = a.Id
	}
	identity.Login = a.Id
	identity.User = user
	if a.RoleNames == "管理员" {
		identity.Role = userAdmin
	} else {
		identity.Role = userNormal
	}
}
