package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	pb "github.com/Azure/aks-tls-bootstrap/pkg/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

var (
	log *logrus.Logger
)

func GetBootstrapToken(mainLogger *logrus.Logger, clientId string, nextProto string) (string, error) {
	log = mainLogger
	log.WithField("KUBERNETES_EXEC_INFO", os.Getenv("KUBERNETES_EXEC_INFO")).Debug("parsing KUBERNETES_EXEC_INFO variable")
	kubernetesExecInfoVar := os.Getenv("KUBERNETES_EXEC_INFO")
	if kubernetesExecInfoVar == "" {
		return "", fmt.Errorf("KUBERNETES_EXEC_INFO variable not found")
	}

	execCredential := &ExecCredential{}
	err := json.Unmarshal([]byte(kubernetesExecInfoVar), execCredential)
	if err != nil {
		return "", err
	}

	serverUrl, err := url.Parse(execCredential.Spec.Cluster.Server)
	if err != nil {
		return "", fmt.Errorf("failed to parse server URL: %v", err)
	}
	server := serverUrl.Hostname() + ":" + serverUrl.Port()

	pemCAs, err := base64.StdEncoding.DecodeString(execCredential.Spec.Cluster.CertificateAuthorityData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 cluster certificates")
	}

	tlsRootStore := x509.NewCertPool()
	ok := tlsRootStore.AppendCertsFromPEM(pemCAs)
	if !ok {
		return "", fmt.Errorf("failed to load cluster root CA(s)")
	}

	tlsConfig := &tls.Config{
		RootCAs:            tlsRootStore,
		InsecureSkipVerify: execCredential.Spec.Cluster.InsecureSkipTlsVerify,
	}
	if nextProto != "" {
		tlsConfig.NextProtos = []string{nextProto, "h2"}
	}

	log.Info("retrieving Azure AD token")
	token, err := GetAuthToken(log, clientId)
	if err != nil {
		return "", err
	}

	perRPC := oauth.NewOauthAccess(&oauth2.Token{
		AccessToken: token,
	})

	conn, err := grpc.Dial(server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(perRPC))
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %v", execCredential.Spec.Cluster.Server, err)
	}
	defer conn.Close()

	pbClient := pb.NewAKSBootstrapTokenRequestClient(conn)

	log.Info("retrieving IMDS instance data")
	instanceData, err := GetInstanceData()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance metadata from IMDS: %v", err)
	}

	log.Infof("retrieving nonce from TLS bootstrap token server at %s", server)
	nonceRequest := pb.NonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
	}
	nonce, err := pbClient.GetNonce(context.Background(), &nonceRequest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a nonce: %v", err)
	}
	log.Infof("nonce reply is %s", nonce.Nonce)

	log.Info("retrieving IMDS attested data")
	attestedData, err := GetAttestedData(nonce.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve attested data from IMDS: %v", err)
	}

	log.Info("retrieving bootstrap token from TLS bootstrap token server")
	tokenRequest := pb.TokenRequest{
		ResourceId:   instanceData.Compute.ResourceID,
		Nonce:        nonce.Nonce,
		AttestedData: attestedData.Signature,
	}
	tokenReply, err := pbClient.GetToken(context.Background(), &tokenRequest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a token: %v", err)
	}
	log.Info("received token reply")

	//execCredential := &ExecCredential{}
	execCredential.APIVersion = "client.authentication.k8s.io/v1"
	execCredential.Kind = "ExecCredential"
	execCredential.Status.Token = tokenReply.Token
	execCredential.Status.ExpirationTimestamp = tokenReply.Expiration

	execCredentialBytes, err := json.Marshal(execCredential)
	if err != nil {
		return "", fmt.Errorf("failed to marshal execCredential")
	}
	return string(execCredentialBytes), nil
}
