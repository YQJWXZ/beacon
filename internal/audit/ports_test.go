package audit

import "testing"

func TestSplitEphemeral(t *testing.T) {
	in := []Listen{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22},
		{Proto: "udp", Addr: "0.0.0.0", Port: 58127},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 8080},
	}
	out, skipped := SplitEphemeral(in)
	if len(out) != 2 || skipped != 1 {
		t.Fatalf("out=%d skipped=%d", len(out), skipped)
	}
	if !IsEphemeral(58127) || IsEphemeral(8080) {
		t.Fatal("range check wrong")
	}
}
