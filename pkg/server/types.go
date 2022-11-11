package server

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	pb "github.com/Azure/aks-tls-bootstrap/pkg/proto"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	coreV1Types "k8s.io/client-go/kubernetes/typed/core/v1"
)

type TlsBootstrapServer struct {
	SignerHostName          string
	AllowedClientIds        []string
	requests                map[string]*Request
	JwksUrl                 string
	Log                     *logrus.Entry
	k8sClientSet            *kubernetes.Clientset
	kubeSystemSecretsClient coreV1Types.SecretInterface
	RootCertPath            string
	IntermediateCertPath    string
	rootCertPool            *x509.CertPool
	intermediateCertPool    *x509.CertPool
	TenantId                string
	tlsConfig               *tls.Config
	httpClient              *http.Client
	pb.UnimplementedAKSBootstrapTokenRequestServer
}

type AzureADTokenClaims struct {
	ClaimNames struct {
		Groups string `json:"groups"`
	} `json:"_claim_names"`
	ClaimSources struct {
		Src1 struct {
			Endpoint string `json:"endpoint"`
		} `json:"src1"`
	} `json:"_claim_sources"`
	Acr               string   `json:"acr"`
	Aio               string   `json:"aio"`
	Amr               []string `json:"amr"`
	AppId             string   `json:"appid"`
	AppIdAcr          string   `json:"appidacr"`
	Azp               string   `json:"azp"`
	Azpacr            string   `json:"azpacr"`
	Deviceid          string   `json:"deviceid"`
	FamilyName        string   `json:"family_name"`
	GivenName         string   `json:"given_name"`
	Groups            []string `json:"groups"`
	HasGroups         bool     `json:"hasgroups"`
	Idp               string   `json:"idp"`
	Ipaddr            string   `json:"ipaddr"`
	Name              string   `json:"name"`
	Oid               string   `json:"oid"`
	OnpremSid         string   `json:"onprem_sid"`
	PreferredUsername string   `json:"preferred_username"`
	Puid              string   `json:"puid"`
	Rh                string   `json:"rh"`
	Roles             []string `json:"roles"`
	Scp               string   `json:"scp"`
	Tid               string   `json:"tid"`
	UniqueName        string   `json:"unique_name"`
	Upn               string   `json:"upn"`
	Uti               string   `json:"uti"`
	Ver               string   `json:"ver"`
	Wids              []string `json:"wids"`
	XmsTcdt           int64    `json:"xms_tcdt"`
	jwt.StandardClaims
}

type Request struct {
	Nonce      string
	Expiration time.Time
	ResourceId string
	VmId       string
	VmName     string
}

type AttestedData struct {
	LicenseType string `json:"licenseType,omitempty"`
	Nonce       string `json:",omitempty"`
	Plan        struct {
		Name      string `json:"name,omitempty"`
		Product   string `json:"product,omitempty"`
		Publisher string `json:"publisher,omitempty"`
	} `json:",omitempty"`
	SubscriptionId string `json:"subscriptionId"`
	Sku            string `json:"sku,omitempty"`
	Timestamp      struct {
		CreatedOn string `json:"createdOn"`
		ExpiresOn string `json:"expiresOn"`
	} `json:"timestamp"`
	VmId string `json:"vmId"`
}

// TODO: duped from client package.
type KubeletAzureJson struct {
	ClientId               string `json:"aadClientId"`
	ClientSecret           string `json:"aadClientSecret"`
	TenantId               string `json:"tenantId"`
	UserAssignedIdentityID string `json:"userAssignedIdentityID"`
}
