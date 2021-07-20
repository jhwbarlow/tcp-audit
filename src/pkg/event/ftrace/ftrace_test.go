package ftrace

import (
	"testing"
)

func TestParse(t *testing.T) {
	eventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	_, err := toEvent(eventTrace)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}
}
