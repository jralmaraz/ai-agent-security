package identity

import "encoding/json"

// jsonUnmarshal is a thin wrapper so chain.go doesn't need its own import block.
var jsonUnmarshal = json.Unmarshal
