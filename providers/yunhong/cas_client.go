package yunhong

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sync"

	log "github.com/Sirupsen/logrus"
	"crypto/tls"
	"github.com/rancher/rancher-auth-service/model"
	"strings"
)

// Client configuration options
type Options struct {
	URL         *url.URL     // URL to the CAS server
	Client      *http.Client // Custom http client to allow options for http connections
	SendService bool         // Custom sendService to determine whether you need to send service param
	ServiceURL  string     // custom local service url
}

// Client implements the main protocol
type Client struct {
	url     *url.URL
	client  *http.Client

	mu          sync.Mutex
	sessions    map[string]string
	sendService bool
	serviceUrl  string
}

// NewClient creates a Client with the provided Options.
func NewClient(options *Options) *Client {
	var client *http.Client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if options.Client != nil {
		client = options.Client
	} else {
		client = &http.Client{Transport: tr}
	}

	return &Client{
		url:         options.URL,
		client:      client,
		sessions:    make(map[string]string),
		sendService: options.SendService,
		serviceUrl:  options.ServiceURL,
	}
}


//The following is added for Yunhong auth Project
func (c *Client)InitRequest(w http.ResponseWriter, r *http.Request, t string, isTest string) (string, error) {
	return c.getSession(w, r, t, isTest)
}

// UserInfoUrlForRequest determines the URL for the user detailed information.
func (c *Client) UserInfoUrlForRequest(config *model.YunhongConfig, user string) (string, error) {
	split := strings.SplitN(user, ":", 2)
	userType, userId := split[0], split[1]
	uo, _ := url.Parse(config.CasServerAddress)
	var u *url.URL
	var err error
	if userType == "0" {
		u, err = uo.Parse(path.Join(uo.Path, "v1/users"))
	} else {
		u, err = uo.Parse(path.Join(uo.Path, "v1/ldap/sdk/users"))
	}
	if err != nil {
		return "", err
	}

	q := u.Query()
	if userType == "0" {
		q.Add("id", userId)
	} else {
		q.Add("account", userId)
	}

	q.Add("systemId", config.CasServiceId)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// UserMatchUrlForRequest determines the URL for the user detailed information.
func (c *Client) SearchUrlForRequest(config *model.YunhongConfig, pattern string, userType int) (string, error) {
	uo, _ := url.Parse(config.CasServerAddress)
	var u *url.URL
	var err error
	if userType == 0 {
		u, err = uo.Parse(path.Join(uo.Path, "v1/users"))
	} else {
		u, err = uo.Parse(path.Join(uo.Path, "v1/ldap/sdk/users"))
	}
	if err != nil {
		return "", err
	}

	q := u.Query()
	if userType == 0 {
		q.Add("idLike", pattern)
	} else {
		q.Add("accountLike", pattern)
	}

	q.Add("systemId", config.CasServiceId)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// SendHeartUrlForRequest determines the URL for the heartbeat check.
func (c *Client) SendHeartUrlForRequest(config *model.YunhongConfig) (string, error) {
	uo, _ := url.Parse(config.CasServerAddress)
	subPath := "v1/systems/" + config.CasServiceId + "/heartbeat"
	u, err := uo.Parse(path.Join(uo.Path, subPath))
	if err != nil {
		return "", err
	}

	q := u.Query()
	u.RawQuery = q.Encode()

	return u.String(), nil
}


func (c *Client)GetFromYunhong(config *model.YunhongConfig, user string) (*http.Response, error) {
	url, err := c.UserInfoUrlForRequest(config, user)

	if err != nil {
		log.Error(err)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error(err)
	}

	req.Header.Add("User-Agent", "Golang CAS client gopkg.in/cas")

	resp, err := c.client.Do(req)
	if err != nil {
		log.Errorf("Received error from yunhong: %v", err)
		return resp, err
	}

	return resp, nil
}

func (c *Client)SearchFromYunhong(config *model.YunhongConfig, pattern string, userType int) (*http.Response, error) {
	url, err := c.SearchUrlForRequest(config, pattern, userType)

	if err != nil {
		log.Error(err)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error(err)
	}

	req.Header.Add("User-Agent", "Golang CAS client gopkg.in/cas")

	resp, err := c.client.Do(req)
	if err != nil {
		log.Errorf("Received error from yunhong: %v", err)
		return resp, err
	}

	return resp, nil
}

func (c *Client)SendHeartbeat(config *model.YunhongConfig) {
	url, err := c.SendHeartUrlForRequest(config)
	if err != nil {
		log.Error(err)
	}
	log.Debugf("Send heartbeat message to yunhong url: %s", url)

	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		log.Error(err)
	}
	req.Header.Add("User-Agent", "Golang CAS client gopkg.in/cas")

	resp, err := c.client.Do(req)
	if err != nil {
		log.Errorf("Received error from yunhong about heartbeat: %v", err)
		return
	}
	resp.Body.Close()
	return
}

func (c* Client)UpdateURL(serverUrl string, serviceUrl string) {
	url, _ := url.Parse(serverUrl)
	c.url = url
	c.serviceUrl = serviceUrl
}
//-----------------------end-----------------------------

// requestURL determines an absolute URL from the http.Request.
func requestURL(r *http.Request) (*url.URL, error) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		return nil, err
	}

	u.Host = r.Host
	u.Scheme = "http"

	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		u.Scheme = scheme
	} else if r.TLS != nil {
		u.Scheme = "https"
	}

	return u, nil
}

// LoginUrlForRequest determines the CAS login URL for the http.Request.
func (c *Client) LoginUrlForRequest(r *http.Request) (string, error) {
	u, err := c.url.Parse(path.Join(c.url.Path, "login"))
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("service", c.serviceUrl)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// LogoutUrlForRequest determines the CAS logout URL for the http.Request.
func (c *Client) LogoutUrlForRequest(r *http.Request) (string, error) {
	u, err := c.url.Parse(path.Join(c.url.Path, "logout"))
	if err != nil {
		return "", err
	}

	if c.sendService {
		q := u.Query()
		q.Add("service", c.serviceUrl)
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}

// ServiceValidateUrlForRequest determines the CAS serviceValidate URL for the ticket and http.Request.
func (c *Client) ServiceValidateUrlForRequest(ticket string, r *http.Request, isTest string) (string, error) {
	u, err := c.url.Parse(path.Join(c.url.Path, "p3/serviceValidate"))
	if err != nil {
		return "", err
	}

	var serviceUrl string
	if isTest != "" {
		serviceUrl = c.serviceUrl + "?isTest=true"
	} else {
		serviceUrl = c.serviceUrl
	}

	q := u.Query()
	q.Add("service", serviceUrl)
	q.Add("ticket", ticket)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ValidateUrlForRequest determines the CAS validate URL for the ticket and http.Request.
func (c *Client) ValidateUrlForRequest(ticket string, r *http.Request, isTest string) (string, error) {
	u, err := c.url.Parse(path.Join(c.url.Path, "p3/validate"))
	if err != nil {
		return "", err
	}

	var serviceUrl string
	if isTest != "" {
		serviceUrl = c.serviceUrl + "/?isTest=true"
	} else {
		serviceUrl = c.serviceUrl
	}

	q := u.Query()
	q.Add("service", serviceUrl)
	q.Add("ticket", ticket)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// validateTicket performs CAS ticket validation with the given ticket and service.
//
// If the request returns a 404 then validateTicketCas1 will be returned.
func (c *Client) validateTicket(ticket string, service *http.Request, isTest string) (string, error) {
	serviceUrl, _ := requestURL(service)
	log.Debugf("Validating ticket %v for service %v", ticket, serviceUrl)
	u, err := c.ServiceValidateUrlForRequest(ticket, service, isTest)
	if err != nil {
		return "", err
	}

	r, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}


	r.Header.Add("User-Agent", "Golang CAS client gopkg.in/cas")

	resp, err := c.client.Do(r)
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusNotFound {
		return c.validateTicketCas1(ticket, service, isTest)
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cas: validate ticket: %v", string(body))
	}

	success, err := ParseServiceResponse(body)
	if err != nil {
		return "", err
	}

	log.Infof("Parsed ServiceResponse: %#v", success)

	return success.User, nil
}

// validateTicketCas1 performs CAS protocol 1 ticket validation.
func (c *Client) validateTicketCas1(ticket string, service *http.Request, isTest string) (string, error) {
	u, err := c.ValidateUrlForRequest(ticket, service, isTest)
	if err != nil {
		return "", err
	}

	r, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}

	r.Header.Add("User-Agent", "Golang CAS client gopkg.in/cas")

	log.Info("Attempting ticket validation with %v", r.URL)

	resp, err := c.client.Do(r)
	if err != nil {
		return "", err
	}

	log.Info("Request %v %v returned %v",
		r.Method, r.URL,
		resp.Status)

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return "", err
	}

	body := string(data)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cas: validate ticket: %v", body)
	}

	if body == "no\n\n" {
		return "", nil // not logged in
	}

	success := &AuthenticationResponse{
		User: body[4 : len(body)-1],
	}

	log.Infof("Parsed ServiceResponse: %#v", success)

	return success.User, nil
}

// getSession finds or creates a session for the request.
//
// A cookie is set on the response if one is not provided with the request.
// Validates the ticket if the URL parameter is provided.
func (c *Client) getSession(w http.ResponseWriter, r *http.Request, ticket string, isTest string) (string, error){
	if ticket != "" {
		if user, err := c.validateTicket(ticket, r, isTest); err == nil {
			log.Debugf("Validated ticket %s for %s", ticket, user)
			return user, nil
		} else {
			log.Errorf("Error validating ticket: %v", err)
			return "", err // allow ServeHTTP()
		}
	}
	return "", fmt.Errorf("No tickets specified")
}