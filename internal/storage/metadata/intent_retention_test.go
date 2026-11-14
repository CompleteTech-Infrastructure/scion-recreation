package metadata_test

import (
	"context"
	"strings"
	"testing"
	"unsafe"

	"canopy.local/canopy/internal/storage/metadata"
)

// StringData is used only to inspect ownership; the input strings are ordinary
// safe slices, and neither their memory nor the returned strings are mutated.
func TestIntentOwnsBoundedStrings(t *testing.T) {
	for _, size := range []struct {
		name       string
		key, event int
	}{{"one-byte", 1, 1}, {"maximum", metadata.MaxMutationKeyBytes, metadata.MaxPublicationEventBytes}} {
		t.Run(size.name, func(t *testing.T) {
			backing := strings.Repeat("x", 32<<20)
			key := backing[11 : 11+size.key]
			event := metadata.EventID(backing[2048 : 2048+size.event])
			s, r := intentRequest(t)
			r.Mutation.Key, r.Event = key, event
			digest, err := metadata.PublicationRequestDigest(context.Background(), s, r)
			if err != nil {
				t.Fatal(err)
			}
			r.Mutation.RequestDigest = digest
			intent, err := metadata.NewPublicationIntent(context.Background(), s, r)
			if err != nil {
				t.Fatal(err)
			}
			status, err := metadata.NewPublicationStatusIntent(context.Background(), s, key)
			if err != nil {
				t.Fatal(err)
			}
			if intent.MutationKey() != key || intent.Event() != event || intent.Digest() != digest || intent.Validate() != nil || status.MutationKey() != key || status.Validate() != nil {
				t.Fatal("intent changed accepted input or digest")
			}
			if unsafe.StringData(intent.MutationKey()) == unsafe.StringData(key) {
				t.Error("publication key retains caller backing")
			}
			if unsafe.StringData(string(intent.Event())) == unsafe.StringData(string(event)) {
				t.Error("publication event retains caller backing")
			}
			if unsafe.StringData(status.MutationKey()) == unsafe.StringData(key) {
				t.Error("status key retains caller backing")
			}
		})
	}
}
