package main

import (
	"context"
	"fmt"

	"github.com/zricethezav/gitleaks/v8/detect"
)

type secretDetector struct {
	detector *detect.Detector
}

func newSecretDetector() (*secretDetector, error) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}

	return &secretDetector{
		detector: detector,
	}, nil
}

func (sd *secretDetector) handleWebhook(_ context.Context, message Message) error {
	findings := sd.detector.DetectBytes(message.Params)
	if len(findings) > 0 {
		return fmt.Errorf("found some secrets: %+v", findings)
	}
	return nil
}
