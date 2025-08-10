package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

type phraseDetector struct {
	phrase []byte
}

func newPhraseDetector(phrase string) *phraseDetector {
	return &phraseDetector{
		phrase: []byte(strings.ToLower(phrase)),
	}
}

func (pd *phraseDetector) handleWebhook(_ context.Context, message Message) error {
	if len(pd.phrase) == 0 {
		return nil
	}

	if bytes.Contains(bytes.ToLower(message.Params), pd.phrase) {
		return fmt.Errorf("found phrase %q in message", pd.phrase)
	}

	return nil
}
