package huawei

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	client  *http.Client
}

type DeviceInfo struct {
	DeviceName      string `xml:"DeviceName"`
	SerialNumber    string `xml:"SerialNumber"`
	IMEI            string `xml:"Imei"`
	IMSI            string `xml:"Imsi"`
	HardwareVersion string `xml:"HardwareVersion"`
	SoftwareVersion string `xml:"SoftwareVersion"`
}

type Status struct {
	ConnectionStatus    string `xml:"ConnectionStatus"`
	SignalStrength      string `xml:"SignalIcon"`
	NetworkType         string `xml:"CurrentNetworkType"`
	WanIPAddress        string `xml:"WanIPAddress"`
	PrimaryDNS          string `xml:"PrimaryDns"`
	SecondaryDNS        string `xml:"SecondaryDns"`
}

func NewClient(ipAddress string) *Client {
	return &Client{
		baseURL: fmt.Sprintf("http://%s", ipAddress),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) GetDeviceInfo() (*DeviceInfo, error) {
	resp, err := c.client.Get(c.baseURL + "/api/device/information")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info DeviceInfo
	if err := xml.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (c *Client) GetStatus() (*Status, error) {
	resp, err := c.client.Get(c.baseURL + "/api/monitoring/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var status Status
	if err := xml.Unmarshal(body, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

func (c *Client) Disconnect() error {
	data := `<?xml version="1.0" encoding="UTF-8"?><request><Action>0</Action></request>`
	
	req, err := http.NewRequest("POST", c.baseURL+"/api/dialup/dial", strings.NewReader(data))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/xml")
	
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	return nil
}

func (c *Client) Connect() error {
	data := `<?xml version="1.0" encoding="UTF-8"?><request><Action>1</Action></request>`
	
	req, err := http.NewRequest("POST", c.baseURL+"/api/dialup/dial", strings.NewReader(data))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/xml")
	
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	return nil
}