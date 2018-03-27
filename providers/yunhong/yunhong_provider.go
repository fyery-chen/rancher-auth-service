package yunhong

import (
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
	v1client "github.com/rancher/go-rancher/client"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"gopkg.in/cas.v2"
)

//Constants for github
const (
	Name                            = "yunhong"
	Config                          = Name + "config"
	TokenType                       = Name + "jwt"
	UserType                        = Name + "_user"
	OrgType                         = Name + "_org"
	TeamType                        = Name + "_team"
	casServerSetting                = "api.auth.yunhong.casserver.address"
	yunhongAccessModeSetting        = "api.auth.yunhong.access.mode"
	yunhongAllowedIdentitiesSetting = "api.auth.yunhong.allowed.identities"
	casSessionName                  = "_cas_session"
	clientSecretSetting             = "api.auth.yunhong.client.secret"
)

type YHProvider struct {
	yunhongClient *YHClient
}

func init() {
}

//InitializeProvider returns a new instance of the provider
func InitializeProvider() (*YHProvider, error) {
	client := cas.NewClient(&cas.Options{})

	yunhongClient := &YHClient{}
	yunhongClient.casClient = client

	yunhongProvider := &YHProvider{}
	yunhongProvider.yunhongClient = yunhongClient
	return yunhongProvider, nil
}

func (g *YHProvider) ProcessCasAuth(w http.ResponseWriter, r *http.Request) bool {
	url := g.yunhongClient.config.CasServerAddress
	//assigned url config to casClient
	g.yunhongClient.casClient.UpdateURL(url)
	//process request
	g.yunhongClient.casClient.InitRequest(w, r)
	if !cas.IsAuthenticated(r) {
		log.Debugf("Yunhong auth, redirect to cas server for log in")
		cas.RedirectToLogin(w, r)
		return false
	}

	if r.URL.Path == "/logout" {//if logout request, then redirect to logout
		cas.RedirectToLogout(w, r)
		return false
	}
	return true
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
	//getAccessToken
	accessToken := json[casSessionName]
	status := 0

	if accessToken != "" {
		log.Debugf("Received AccessToken from cas client %v", accessToken)
		return g.createToken(accessToken)
	}

	return model.Token{}, status, fmt.Errorf("Cannot gerenate token from yunhong, invalid request data")
}

func (g *YHProvider) createToken(accessToken string) (model.Token, int, error) {
	status := 0
	var token = model.Token{Resource: client.Resource{
		Type: "token",
	}}
	token.AccessToken = accessToken
	//getIdentities from accessToken
	//identities, err := g.GetIdentities(accessToken)
	//if err != nil {
	//	log.Errorf("Error getting identities using accessToken from github %v", err)
	//	return model.Token{}, status, err
	//}
	//token.IdentityList = identities
	token.Type = TokenType
	//user, ok := GetUserIdentity(identities, UserType)
	//if !ok {
	//	log.Error("User identity not found using accessToken from github")
	//	return model.Token{}, status, fmt.Errorf("User identity not found using accessToken from github")
	//}
	//token.ExternalAccountID = user.ExternalId
	return token, status, nil
}

//GetUserIdentity returns the "user" from the list of identities
func GetUserIdentity(identities []client.Identity, userType string) (client.Identity, bool) {
	for _, identity := range identities {
		if identity.ExternalIdType == userType {
			return identity, true
		}
	}
	return client.Identity{}, false
}

//RefreshToken re-authenticates and generate a new token
func (g *YHProvider) RefreshToken(json map[string]string) (model.Token, int, error) {
	accessToken := json["accessToken"]
	if accessToken != "" {
		log.Debugf("GitHubIdentityProvider RefreshToken called for accessToken %v", accessToken)
		return g.createToken(accessToken)
	}
	return model.Token{}, 0, fmt.Errorf("Cannot refresh token from github, no access token found in request")
}

//GetIdentities returns list of user and group identities associated to this token
func (g *YHProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	return identities, nil
}

//GetIdentity returns the identity by externalID and externalIDType
func (g *YHProvider) GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	identity := client.Identity{Resource: client.Resource{
		Type: "identity",
	}}

	return identity, nil
}

//SearchIdentities returns the identity by name
func (g *YHProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

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
	return settings
}

//GetProviderSettingList returns the provider specific db setting list
func (g *YHProvider) GetProviderSettingList(listOnly bool) []string {
	var settings []string
	settings = append(settings, casServerSetting)

	return settings
}

//AddProviderConfig adds the provider config into the generic config using the settings from db
func (g *YHProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
	yunhongConfig := model.YunhongConfig{Resource: client.Resource{
		Type: "yunhongconfig",
	}}
	yunhongConfig.CasServerAddress = providerSettings[casServerSetting]

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
	redirect := ""

	return redirect
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
	settings = append(settings, clientSecretSetting)
	return settings
}

func (g *YHProvider) IsIdentityLookupSupported() bool {
	return true
}