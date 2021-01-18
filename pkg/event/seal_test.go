package event

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigestSeal(t *testing.T) {
	expectedBytes := `{"d":"EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8"}`
	s, err := NewDigestSeal("EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8")
	assert.NoError(t, err)

	sealBytes, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.JSONEq(t, expectedBytes, string(sealBytes))
}

func TestRootSeal(t *testing.T) {
	expectedBytes := `{"rd":"EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8"}`

	s, err := NewRootSeal("EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8")
	assert.NoError(t, err)

	sealBytes, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.JSONEq(t, expectedBytes, string(sealBytes))
}

func TestEventSeal(t *testing.T) {
	expectedBytes := `{"i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","d":"EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8","s":"0"}`

	s, err := NewEventSeal("EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8", "ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY", "0")
	assert.NoError(t, err)

	sealBytes, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.JSONEq(t, expectedBytes, string(sealBytes))
}

func TestEventLocationSeal(t *testing.T) {
	expectedBytes := `{"i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","d":"EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8","s":"0","t":"vrc"}`

	s, err := NewEventLocationSeal("EFGlDJesPRaa1AQJo8FD4DKR82VfVyp2Q027l4HhLTk8", "ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY", "0", VRC)
	assert.NoError(t, err)

	sealBytes, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.JSONEq(t, expectedBytes, string(sealBytes))
}
