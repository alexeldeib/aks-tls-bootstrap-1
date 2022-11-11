package server

import (
	"context"
	"fmt"
	"time"

	pb "github.com/Azure/aks-tls-bootstrap/pkg/proto"
	"github.com/sirupsen/logrus"
)

func (s *TlsBootstrapServer) GetToken(ctx context.Context, tokenRequest *pb.TokenRequest) (*pb.TokenResponse, error) {
	requestLog := s.Log.WithFields(logrus.Fields{
		"nonce": tokenRequest.Nonce,
	})
	requestLog.Infof("received token request")

	attestedData, err := s.validateAttestedData(tokenRequest.AttestedData, s.SignerHostName)
	if err != nil {
		err = fmt.Errorf("failed to validate attested data: %v", err)
		requestLog.Error(err)
		return nil, err
	}
	requestLog.Infof("validated attested data")

	err = s.validateRequestExistsAndCurrent(attestedData)
	if err != nil {
		err = fmt.Errorf("failed to match token request nonce to valid existing nonce: %v", err)
		requestLog.Error(err)
		return nil, err
	}
	requestLog = requestLog.WithFields(logrus.Fields{
		"resourceId": s.requests[tokenRequest.Nonce].ResourceId,
		"vmId":       attestedData.VmId,
	})

	s.requests[tokenRequest.Nonce].VmId = attestedData.VmId
	requestLog.Info("validating VM ID against ARM")
	err = s.validateVmId(tokenRequest.Nonce)
	if err != nil {
		err = fmt.Errorf("failed to validate VM ID: %v", err)
		requestLog.Error(err)
		return nil, err
	}

	bootstrapTokenSecret, expiration, err := s.createBootstrapTokenSecret(s.requests[tokenRequest.Nonce].VmName)
	if err != nil {
		requestLog.Error(err)
		return nil, err
	}

	response := &pb.TokenResponse{}
	response.Token = bootstrapTokenSecret
	response.Expiration = expiration

	delete(s.requests, tokenRequest.Nonce)
	requestLog.Info("returning token and flushing nonce from cache")
	return response, nil
}

func (s *TlsBootstrapServer) validateRequestExistsAndCurrent(attestedData *AttestedData) error {
	nonce, exists := s.requests[attestedData.Nonce]
	if !exists {
		return fmt.Errorf("nonce %s not found in cache", attestedData.Nonce)
	}

	if nonce.Expiration.Before(time.Now()) {
		return fmt.Errorf("nonce %s expired at %s", attestedData.Nonce, nonce.Expiration.String())
	}

	return nil
}
