// helpers_test.go — shared test helpers for the W6.11.8/9/10 additions.
package observability_test

// last returns the subject + payload of the most recently published message,
// or ("", nil) if nothing was published. Reuses the capturePublisher double
// defined in nats_publisher_test.go.
func (c *capturePublisher) last() (string, []byte) {
	msgs := c.Messages()
	if len(msgs) == 0 {
		return "", nil
	}
	m := msgs[len(msgs)-1]
	return m.Subject, m.Payload
}

// newRecordingPublisher is an alias constructor for the capturePublisher
// double, used by the config-reload and CDC tests.
func newRecordingPublisher() *capturePublisher {
	return &capturePublisher{}
}
