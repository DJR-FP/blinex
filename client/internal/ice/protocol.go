package ice

import "encoding/json"

// Offer is sent by the ICE controller to initiate a peer connection.
type Offer struct {
	Ufrag string `json:"ufrag"`
	Pwd   string `json:"pwd"`
}

// Answer is sent by the ICE controlled in response to an Offer.
type Answer struct {
	Ufrag string `json:"ufrag"`
	Pwd   string `json:"pwd"`
}

// Candidate carries a trickle ICE candidate string.
type Candidate struct {
	Candidate string `json:"candidate"`
}

func marshalOffer(o Offer) string {
	b, _ := json.Marshal(o)
	return string(b)
}

func unmarshalOffer(s string) (Offer, error) {
	var o Offer
	return o, json.Unmarshal([]byte(s), &o)
}

func marshalAnswer(a Answer) string {
	b, _ := json.Marshal(a)
	return string(b)
}

func unmarshalAnswer(s string) (Answer, error) {
	var a Answer
	return a, json.Unmarshal([]byte(s), &a)
}

func marshalCandidate(c Candidate) string {
	b, _ := json.Marshal(c)
	return string(b)
}

func unmarshalCandidate(s string) (Candidate, error) {
	var c Candidate
	return c, json.Unmarshal([]byte(s), &c)
}
