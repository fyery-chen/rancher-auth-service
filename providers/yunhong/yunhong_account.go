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

type UserAdAccount []*UserDetailInfo

type UserDetailInfo struct {
	Id         		string `json:"id,omitempty"`
	Name       		string `json:"name,omitempty"`
	Account       	string `json:"account,omitempty"`
	State      		int    `json:"state,omitempty"`
	UserOnline 		int    `json:"userOnline,omitempty"`
	RoleIds    		string `json:"roleIds,omitempty"`
	RoleNames       string `json:"roleNames,omitempty"`
	SystemIds  		string `json:"systemIds,omitempty"`
	UserType   	   	int    `json:"userType,omitempty"`
}

func (a *UserDetailInfo) toIdentity(externalIDType string, identity *client.Identity, user bool) {
	if a.UserType == 0 {
		identity.ExternalId = a.Id + strconv.Itoa(a.UserType)
		identity.Login = a.Id
		if a.Name != "" {
			identity.Name = a.Name
		} else {
			identity.Name = a.Id
		}
	} else {
		identity.ExternalId = a.Account + strconv.Itoa(a.UserType)
		identity.Login = a.Account
		identity.Name = a.Name
	}

	identity.Resource.Id = externalIDType + ":" + a.Id + strconv.Itoa(a.UserType)
	identity.ExternalIdType = externalIDType

	identity.User = user
	if a.RoleNames == "管理员" {
		identity.Role = userAdmin
	} else {
		identity.Role = userNormal
	}
}
