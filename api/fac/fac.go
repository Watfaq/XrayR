package fac

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"

	"github.com/XrayR-project/XrayR/api"
)

// APIClient create a api client to the panel.
type APIClient struct {
	client              *resty.Client
	APIHost             string
	NodeID              string
	Key                 string
	NodeType            string
	EnableVless         bool
	VlessFlow           string
	SpeedLimit          float64
	DeviceLimit         int
	DisableCustomConfig bool
	LocalRuleList       []api.DetectRule
	LastReportOnline    map[int]int
	access              sync.Mutex
	version             string
	eTags               map[string]string
}

// New create api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()

	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(_ *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})

	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	client.SetQueryParam("key", apiConfig.Key)
	// Add support for muKey
	client.SetQueryParam("muKey", apiConfig.Key)
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)

	return &APIClient{
		client:              client,
		NodeID:              apiConfig.NodeID,
		Key:                 apiConfig.Key,
		APIHost:             apiConfig.APIHost,
		NodeType:            apiConfig.NodeType,
		EnableVless:         apiConfig.EnableVless,
		VlessFlow:           apiConfig.VlessFlow,
		SpeedLimit:          apiConfig.SpeedLimit,
		DeviceLimit:         apiConfig.DeviceLimit,
		LocalRuleList:       localRuleList,
		DisableCustomConfig: apiConfig.DisableCustomConfig,
		LastReportOnline:    make(map[int]int),
		eTags:               make(map[string]string),
	}
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (localRuleList []api.DetectRule) {
	localRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		defer func(file *os.File) {
			err = file.Close()
			if err != nil {
				log.Printf("Error when closing file: %s", err)
			}
		}(file)
		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return localRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			localRuleList = append(localRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Errorf("Error while reading file: %s", err)
			return localRuleList
		}
	}

	return localRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %w", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %w", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.Ret != 1 {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("ret %s invalid", string(res))
	}
	return response, nil
}

// GetNodeInfo will pull NodeInfo Config from ssPanel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/mod_mu/nodes/%s/info", c.NodeID)
	res, err := c.client.R().
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["node"] {
		c.eTags["node"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(NodeInfoResponse)

	if err = json.Unmarshal(response.Data, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %w", reflect.TypeOf(nodeInfoResponse), err)
	}

	c.version = nodeInfoResponse.Version

	nodeInfo, err = c.ParseSSPanelNodeInfo(nodeInfoResponse)
	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s, \nPlease check the doc of custom_config for help: "+
			"https://xrayr-project.github.io/XrayR-doc/dui-jie-sspanel/sspanel/sspanel_custom_config", string(res), err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form ssPanel
func (c *APIClient) GetUserList() (userList *[]api.UserInfo, err error) {
	path := "/mod_mu/users"
	res, err := c.client.R().
		SetQueryParam("node_id", c.NodeID).
		SetHeader("If-None-Match", c.eTags["users"]).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["users"] {
		c.eTags["users"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new([]UserResponse)

	if err = json.Unmarshal(response.Data, userListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %w", reflect.TypeOf(userListResponse), err)
	}
	userList, err = c.ParseUserListResponse(userListResponse)
	if err != nil {
		res, _ := json.Marshal(userListResponse)
		return nil, fmt.Errorf("parse user list failed: %s", string(res))
	}
	return userList, nil
}

// ReportNodeStatus reports the node status to the ssPanel
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	// Determine whether a status report is in need
	if compareVersion(c.version, "2023.2") == -1 {
		path := fmt.Sprintf("/mod_mu/nodes/%s/info", c.NodeID)
		systemLoad := SystemLoad{
			Uptime: strconv.FormatUint(nodeStatus.Uptime, 10),
			Load:   fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.Mem/100, nodeStatus.Disk/100),
		}

		res, err := c.client.R().
			SetBody(systemLoad).
			SetResult(&Response{}).
			ForceContentType("application/json").
			Post(path)

		_, err = c.parseResponse(res, path, err)
		if err != nil {
			return err
		}
	}
	return nil
}

// ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
		reportOnline[user.UID]++ // will start from 1 if key doesn’t exist
	}
	c.LastReportOnline = reportOnline // Update LastReportOnline

	postData := &PostData{Data: data}
	path := "/mod_mu/users/aliveip"
	res, err := c.client.R().
		SetQueryParam("node_id", c.NodeID).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}
	postData := &PostData{Data: data}
	path := "/mod_mu/users/traffic"
	res, err := c.client.R().
		SetQueryParam("node_id", c.NodeID).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule will pull the audit rule form ssPanel
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	path := "/mod_mu/func/detect_rules"
	res, err := c.client.R().
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags["rules"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.RuleNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["rules"] {
		c.eTags["rules"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	ruleListResponse := new([]RuleItem)

	if err := json.Unmarshal(response.Data, ruleListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %w", reflect.TypeOf(ruleListResponse), err)
	}

	for _, r := range *ruleListResponse {
		ruleList = append(ruleList, api.DetectRule{
			ID:      r.ID,
			Pattern: regexp.MustCompile(r.Content),
		})
	}
	return &ruleList, nil
}

// ReportIllegal reports the user illegal behaviors
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			ID:  r.RuleID,
			UID: r.UID,
		}
	}
	postData := &PostData{Data: data}
	path := "/mod_mu/users/detectlog"
	res, err := c.client.R().
		SetQueryParam("node_id", c.NodeID).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}

// ParseUserListResponse parse the response for the given node info format
func (c *APIClient) ParseUserListResponse(userInfoResponse *[]UserResponse) (*[]api.UserInfo, error) {
	c.access.Lock()
	// Clear Last report log
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()

	var deviceLimit, localDeviceLimit int
	var speedLimit uint64
	var userList []api.UserInfo
	for _, user := range *userInfoResponse {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}

		// If there is still device available, add the user
		if deviceLimit > 0 && user.AliveIP > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[user.ID]; ok {
				lastOnline = v
			}
			// If there are any available device.
			if localDeviceLimit = deviceLimit - user.AliveIP + lastOnline; localDeviceLimit > 0 {
				deviceLimit = localDeviceLimit
				// If this backend server has reported any user in the last reporting period.
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
				// Remove this user.
			} else {
				continue
			}
		}

		if c.SpeedLimit > 0 {
			speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedLimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList = append(userList, api.UserInfo{
			UID:         user.ID,
			UUID:        user.UUID,
			Passwd:      user.Passwd,
			Email:       user.Email,
			SpeedLimit:  speedLimit,
			DeviceLimit: deviceLimit,
			Port:        user.Port,
			Method:      user.Method,
		})
	}

	return &userList, nil
}

// ParseSSPanelNodeInfo parse the response for the given node info format
// Only available for SSPanel version >= 2021.11
func (c *APIClient) ParseSSPanelNodeInfo(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var (
		speedLimit             uint64
		enableTLS, enableVless bool
		alterID                uint16 = 0
		transportProtocol      string
	)

	// Check if custom_config is null
	if len(nodeInfoResponse.CustomConfig) == 0 {
		return nil, errors.New("custom_config is empty, disable custom config")
	}

	nodeConfig := new(CustomConfig)
	err := json.Unmarshal(nodeInfoResponse.CustomConfig, nodeConfig)
	if err != nil {
		return nil, fmt.Errorf("custom_config format error: %w", err)
	}

	if c.SpeedLimit > 0 {
		speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedLimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}

	parsedPort, err := strconv.ParseInt(nodeConfig.OffsetPortNode, 10, 32)
	if err != nil {
		return nil, err
	}
	if parsedPort < 0 || parsedPort > math.MaxUint32 {
		return nil, fmt.Errorf("parsed port %d is out of range for uint32", parsedPort)
	}
	port := uint32(parsedPort)

	switch c.NodeType {
	case api.NodeTypeShadowsocks, api.NodeTypeShadowsocksPlugin:
		transportProtocol = "tcp"
	case "V2ray":
		transportProtocol = nodeConfig.Network

		tlsType := nodeConfig.Security
		if tlsType == "tls" || tlsType == "xtls" {
			enableTLS = true
		}

		if nodeConfig.EnableVless == "1" {
			enableVless = true
		}
	case "Trojan":
		enableTLS = true
		transportProtocol = "tcp"

		// Select transport protocol
		if nodeConfig.Network != "" {
			transportProtocol = nodeConfig.Network // try to read transport protocol from config
		}
	}

	// parse reality config
	realityConfig := new(api.REALITYConfig)
	if nodeConfig.RealityOpts != nil {
		r := nodeConfig.RealityOpts
		realityConfig = &api.REALITYConfig{
			Dest:             r.Dest,
			ProxyProtocolVer: r.ProxyProtocolVer,
			ServerNames:      r.ServerNames,
			PrivateKey:       r.PrivateKey,
			MinClientVer:     r.MinClientVer,
			MaxClientVer:     r.MaxClientVer,
			MaxTimeDiff:      r.MaxTimeDiff,
			ShortIds:         r.ShortIds,
		}
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		AltPort:           nodeConfig.AltPort,
		SpeedLimit:        speedLimit,
		AlterID:           alterID,
		TransportProtocol: transportProtocol,
		Host:              nodeConfig.Host,
		Path:              nodeConfig.Path,
		EnableTLS:         enableTLS,
		EnableVless:       enableVless,
		VlessFlow:         nodeConfig.Flow,
		CypherMethod:      nodeConfig.Method,
		ServiceName:       nodeConfig.Servicename,
		Header:            nodeConfig.Header,
		EnableREALITY:     nodeConfig.EnableREALITY,
		REALITYConfig:     realityConfig,
		ServerKey:         nodeConfig.ServerKey,
	}

	return nodeInfo, nil
}

// compareVersion, version1 > version2 return 1, version1 < version2 return -1, 0 means equal
func compareVersion(version1, version2 string) int {
	n, m := len(version1), len(version2)
	i, j := 0, 0
	for i < n || j < m {
		x := 0
		for ; i < n && version1[i] != '.'; i++ {
			x = x*10 + int(version1[i]-'0')
		}
		i++ // jump dot
		y := 0
		for ; j < m && version2[j] != '.'; j++ {
			y = y*10 + int(version2[j]-'0')
		}
		j++ // jump dot
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}
