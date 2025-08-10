package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

type phraseDetector struct {
	phrases [][]byte
}

func newPhraseDetector(phrases []string) *phraseDetector {
	ps := make([][]byte, len(phrases))
	for i := range phrases {
		ps[i] = []byte(strings.ToLower(strings.TrimSpace(phrases[i])))
	}
	return &phraseDetector{
		phrases: ps,
	}
}

func (pd *phraseDetector) handleWebhook(_ context.Context, message Message) error {
	for _, phrase := range pd.phrases {
		if len(phrase) != 0 {
			if bytes.Contains(bytes.ToLower(message.Params), phrase) {
				return fmt.Errorf("found phrase %q in message", phrase)
			}
		}
	}

	return nil
}
