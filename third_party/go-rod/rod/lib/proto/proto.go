package proto

import (
	"encoding/json"
	"time"
)

type TargetCreateTarget struct {
	URL string
}

type PageLifecycleEventName string

const PageLifecycleEventNameNetworkAlmostIdle PageLifecycleEventName = "networkAlmostIdle"

type RuntimeRemoteObject struct {
	Type        string          `json:"type,omitempty"`
	Value       json.RawMessage `json:"value,omitempty"`
	Description string          `json:"description,omitempty"`
}

func (r *RuntimeRemoteObject) String() string {
	if r == nil {
		return ""
	}
	if len(r.Value) == 0 {
		return r.Description
	}
	var s string
	if err := json.Unmarshal(r.Value, &s); err == nil {
		return s
	}
	return string(r.Value)
}

type TimeSinceEpoch float64

func (t TimeSinceEpoch) Time() time.Time {
	return time.Unix(0, 0).Add(time.Duration(t * TimeSinceEpoch(time.Second)))
}

type NetworkCookie struct {
	Name     string         `json:"name"`
	Value    string         `json:"value"`
	Domain   string         `json:"domain"`
	Path     string         `json:"path"`
	Expires  TimeSinceEpoch `json:"expires"`
	Secure   bool           `json:"secure"`
	HTTPOnly bool           `json:"httpOnly"`
}
