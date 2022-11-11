package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	pb "github.com/Azure/aks-tls-bootstrap/pkg/proto"
)

func (s *TlsBootstrapServer) removeExpiredNonces() {
	interval := NONCE_EXPIRATION_CHECK_INTERVAL

	s.Log.Infof("starting nonce expiration checker, interval %d second(s)", interval/time.Second)
	ticker := time.NewTicker(interval)

	for range ticker.C {
		for nonce := range s.requests {
			if s.requests[nonce].Expiration.Before(time.Now()) {
				s.Log.Infof("removing expired nonce %s for %s", nonce, s.requests[nonce].ResourceId)
				delete(s.requests, nonce)
			}
		}
	}
}

func generateNonceString() (string, error) {
	rand.Seed(time.Now().Unix())
	bytes := make([]byte, 5)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token for nonce")
	}
	return hex.EncodeToString(bytes), nil
}

func (s *TlsBootstrapServer) GetNonce(ctx context.Context, nonceRequest *pb.NonceRequest) (*pb.NonceResponse, error) {
	requestLog := s.Log.WithField("resourceId", nonceRequest.ResourceId)
	requestLog.Infof("received nonce request")

	var nonceStr string
	var err error
	attempts := 0
	for attempts < 100 {
		attempts++
		nonceStr, err = generateNonceString()
		if err != nil {
			return nil, err
		}
		_, exists := s.requests[nonceStr]
		if !exists {
			break
		}
	}
	if attempts == 100 {
		err := fmt.Errorf("unable to generate a non-colliding nonce after 100 attempts")
		requestLog.Error(err)
		return nil, err
	}

	requestLog = requestLog.WithField("nonce", nonceStr)

	s.requests[nonceStr] = &Request{
		Nonce:      nonceStr,
		ResourceId: nonceRequest.ResourceId,
		Expiration: time.Now().Add(NONCE_LIFETIME),
	}

	requestLog.Info("replying to nonce request")
	return &pb.NonceResponse{
		Nonce: nonceStr,
	}, nil
}
