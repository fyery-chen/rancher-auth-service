package yunhong

import (
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
	v1client "github.com/rancher/go-rancher/client"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"io/ioutil"
	"encoding/json"
	"time"
	"strings"
)

//Constants for github
const (
	Name                            = "yunhong"
	Config                          = Name + "config"
	TokenType                       = Name + "jwt"
	UserType                        = Name + "_user"
	yunhongAccessModeSetting        = "api.auth.yunhong.access.mode"
	yunhongAllowedIdentitiesSetting = "api.auth.yunhong.allowed.identities"
	casServerSetting                = "api.auth.yunhong.casserver.address"
	casServiceIdSetting            	= "api.auth.yunhong.cas.service.id"
	casServiceUrlSetting            = "api.auth.yunhong.cas.service.url"
	defaultDuration                 = 3 * time.Minute
)

var (
	Ticker           *time.Ticker
)

type YHProvider struct {
	yunhongClient *YHClient
}

func init() {
}

//InitializeProvider returns a new instance of the provider
func InitializeProvider() (*YHProvider, error) {
	client := NewClient(&Options{
	})

	yunhongClient := &YHClient{}
	yunhongClient.casClient = client

	yunhongProvider := &YHProvider{}
	yunhongProvider.yunhongClient = yunhongClient
	return yunhongProvider, nil
}

func (g *YHProvider) ProcessCasAuth(w http.ResponseWriter, r *http.Request, t string, isTest string) (bool, string) {
	//address url.URL
	g.yunhongClient.casClient.UpdateURL(g.yunhongClient.config.CasServerAddress, g.yunhongClient.config.CasServiceUrl)

	user, err := g.yunhongClient.casClient.InitRequest(w, r, t, isTest)
	if err != nil {
		log.Errorf("Yunhong auth, redirect to cas server: %s", g.GetRedirectURL())
		return false, ""
	}

	return true, user
}

func (g *YHProvider) SendHeartbeatRequest(authConfig model.AuthConfig) {
	if Ticker != nil {
		Ticker.Stop()
	}
	Ticker = time.NewTicker(defaultDuration)
	go func() {
		for _ = range Ticker.C {
			g.yunhongClient.casClient.SendHeartbeat(&authConfig.YunhongConfig)
		}
	}()
}

//GetName returns the name of the provider
func (g *YHProvider) GetName() string {
	return Name
}

//GetUserType returns the string used to identify a user account for this provider
func (g *YHProvider) GetUserType() string {
	return UserType
}

//GenerateToken authenticates the given code and returns the token
func (g *YHProvider) GenerateToken(json map[string]string) (model.Token, int, error) {
	user := json["userAccount"]

    log.Debugf("YunhongIdentityProvider GenerateToken called for user: %v", user)
    return g.createToken(json)
}

func (g *YHProvider) createToken(json map[string]string) (model.Token, int, error) {
	user := json["userAccount"]
	isTest := json["isTest"]
	status := 0
	var identities []client.Identity
	var token = model.Token{Resource: client.Resource{
		Type: "token",
	}}

	identities, err := g.GetIdentities(user)
	if err != nil {
		log.Errorf("Error getting identities using accessToken from yunhong %v", err)
		return model.Token{}, status, err
	}
	token.IdentityList = identities
	token.Type = TokenType
	split := strings.SplitN(user, ":", 2)
	externalId := split[1] + split[0]
	i, ok := GetUserIdentity(identities, UserType, externalId)
	if !ok {
		log.Errorf("User identity %s not found from yunhong", user)
		return model.Token{}, status, fmt.Errorf("User identity not found using accessToken from yunhong")
	}
	if isTest == "true" && i.Role == "user" {
		log.Errorf("User identity %s is not admin", user)
		return model.Token{}, http.StatusForbidden, fmt.Errorf("User identity %s is not admin", user)
	}

	token.AccessToken = i.ExternalId
	token.ExternalAccountID = i.ExternalId
	log.Debugf("get info from yunhong which accessToken: %s, externalAccountID: %s, role: %s",
		token.AccessToken, token.ExternalAccountID, i.Role)

	return token, status, nil
}

//GetUserIdentity returns the "user" from the list of identities
func GetUserIdentity(identities []client.Identity, userType string, externalID string) (client.Identity, bool) {
	for _, identity := range identities {
		if identity.ExternalIdType == userType && identity.ExternalId == externalID {
			return identity, true
		}
	}
	return client.Identity{}, false
}

//RefreshToken re-authenticates and generate a new token
func (g *YHProvider) RefreshToken(json map[string]string) (model.Token, int, error) {
	user := json["userAccount"]
	if user != "" {
		log.Debugf("YunhongIdentityProvider RefreshToken called for user %v", user)
		return g.createToken(json)
	}
	return model.Token{}, 0, fmt.Errorf("Cannot refresh token from Yunhong, no user found in request")
}

//GetIdentities returns list of user and group identities associated to this token
func (g *YHProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	split := strings.SplitN(accessToken, ":", 2)
	userType, _ := split[0], split[1]

	resp, err := g.yunhongClient.casClient.GetFromYunhong(g.yunhongClient.config, accessToken)
	if err != nil {
		return identities, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return identities, err
	}

	if userType == "0" {
		var userInfo UserAccount
		if err := json.Unmarshal(b, &userInfo); err != nil {
			return identities, err
		}

		for _, u := range userInfo.Data {
			userIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}

			u.toIdentity(UserType, &userIdentity, true)
			identities = append(identities, userIdentity)
		}
	} else {
		var userAdInfo UserAdAccount
		if err := json.Unmarshal(b, &userAdInfo); err != nil {
			return identities, err
		}

		for _, u := range userAdInfo {
			userIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}

			u.toIdentity(UserType, &userIdentity, true)
			identities = append(identities, userIdentity)
		}
	}


	return identities, nil
}

//GetIdentity returns the identity by externalID and externalIDType
func (g *YHProvider) GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	identities, err := g.SearchIdentities("", true, "")
	for _, identity := range identities {
		if identity.ExternalIdType == UserType && identity.ExternalId == externalID {
			return identity, nil
		}
	}
	return client.Identity{}, err
}

//SearchIdentities returns the identity by name
func (g *YHProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	//local users
	resp1, err := g.yunhongClient.casClient.SearchFromYunhong(g.yunhongClient.config, name, 0)
	if err != nil {
		return identities, err
	}
	defer resp1.Body.Close()
	var localUserInfo UserAccount

	b1, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		return identities, err
	}

	if err := json.Unmarshal(b1, &localUserInfo); err != nil {
		return identities, err
	}

	for _, u := range localUserInfo.Data {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}

		u.toIdentity(UserType, &userIdentity, true)
		identities = append(identities, userIdentity)
	}

	//ad users
	resp2, err := g.yunhongClient.casClient.SearchFromYunhong(g.yunhongClient.config, name, 1)
	if err != nil {
		return identities, err
	}
	defer resp2.Body.Close()
	var adUserInfo UserAdAccount

	b2, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		return identities, err
	}

	if err := json.Unmarshal(b2, &adUserInfo); err != nil {
		return identities, err
	}

	for _, u := range adUserInfo {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}

		u.toIdentity(UserType, &userIdentity, true)
		identities = append(identities, userIdentity)
	}

	return identities, nil
}

//LoadConfig initializes the provider with the passes config
func (g *YHProvider) LoadConfig(authConfig *model.AuthConfig) error {
	configObj := authConfig.YunhongConfig
	g.yunhongClient.config = &configObj
	return nil
}

//GetConfig returns the provider config
func (g *YHProvider) GetConfig() model.AuthConfig {
	log.Debug("In yunhong getConfig")

	authConfig := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	authConfig.Provider = Config
	authConfig.YunhongConfig = *g.yunhongClient.config

	authConfig.YunhongConfig.Resource = client.Resource{
		Type: "yunhongconfig",
	}

	log.Debug("In yunhong authConfig %v", authConfig)
	return authConfig
}

//GetSettings transforms the provider config to db settings
func (g *YHProvider) GetSettings() map[string]string {
	settings := make(map[string]string)

	settings[casServerSetting] = g.yunhongClient.config.CasServerAddress
	settings[casServiceIdSetting] = g.yunhongClient.config.CasServiceId
	settings[casServiceUrlSetting] = g.yunhongClient.config.CasServiceUrl
	return settings
}

//GetProviderSettingList returns the provider specific db setting list
func (g *YHProvider) GetProviderSettingList(listOnly bool) []string {
	var settings []string
	settings = append(settings, casServerSetting)
	settings = append(settings, casServiceUrlSetting)
	settings = append(settings, casServiceIdSetting)

	return settings
}

//AddProviderConfig adds the provider config into the generic config using the settings from db
func (g *YHProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
	yunhongConfig := model.YunhongConfig{Resource: client.Resource{
		Type: "yunhongconfig",
	}}
	yunhongConfig.CasServerAddress = providerSettings[casServerSetting]
	yunhongConfig.CasServiceUrl = providerSettings[casServiceUrlSetting]
	yunhongConfig.CasServiceId = providerSettings[casServiceIdSetting]

	authConfig.YunhongConfig = yunhongConfig
}

//GetLegacySettings returns the provider specific legacy db settings
func (g *YHProvider) GetLegacySettings() map[string]string {
	settings := make(map[string]string)
	settings["accessModeSetting"] = yunhongAccessModeSetting
	settings["allowedIdentitiesSetting"] = yunhongAllowedIdentitiesSetting
	return settings
}

//GetRedirectURL returns the provider specific redirect URL used by UI
func (g *YHProvider) GetRedirectURL() string {
	url := g.yunhongClient.config.CasServerAddress + "/login?" + "service=" + g.yunhongClient.config.CasServiceUrl
	return url
}

//GetIdentitySeparator returns the provider specific separator to use to separate allowedIdentities
func (g *YHProvider) GetIdentitySeparator() string {
	return ","
}

func (g *YHProvider) TestLogin(testAuthConfig *model.TestAuthConfig, accessToken string, originalLogin string) (int, error) {
	return 0, nil
}

func (g *YHProvider) GetProviderConfigResource() interface{} {
	return model.YunhongConfig{}
}

func (g *YHProvider) CustomizeSchema(schema *v1client.Schema) *v1client.Schema {
	return schema
}

func (g *YHProvider) GetProviderSecretSettings() []string {
	var settings []string
	return settings
}

func (g *YHProvider) IsIdentityLookupSupported() bool {
	return true
}