package engine

import (
	"encoding/base64"
	"encoding/json"
)

type resultJSON Result

type resultJSONEnvelope struct {
	resultJSON
	RequestRawB64  string `json:"request_raw_b64,omitempty"`
	ResponseRawB64 string `json:"response_raw_b64,omitempty"`
}

func (r Result) MarshalJSON() ([]byte, error) {
	payload := resultJSONEnvelope{
		resultJSON: resultJSON(r),
	}
	if len(r.RequestBytes) > 0 {
		payload.RequestRawB64 = base64.StdEncoding.EncodeToString(r.RequestBytes)
	}
	if len(r.ResponseBytes) > 0 {
		payload.ResponseRawB64 = base64.StdEncoding.EncodeToString(r.ResponseBytes)
	}
	return json.Marshal(payload)
}

func (r *Result) UnmarshalJSON(data []byte) error {
	var payload resultJSONEnvelope
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	*r = Result(payload.resultJSON)
	if payload.RequestRawB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(payload.RequestRawB64)
		if err != nil {
			return err
		}
		r.RequestBytes = raw
	}
	if payload.ResponseRawB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(payload.ResponseRawB64)
		if err != nil {
			return err
		}
		r.ResponseBytes = raw
	}
	return nil
}
