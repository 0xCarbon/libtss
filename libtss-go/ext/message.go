package ext

import (
	"fmt"
	"strings"

	"github.com/0xCarbon/libtss-go/tss"
)

type MessagePacket struct {
	Round     int
	SessionID []byte
	From      tss.Identifier
	To        tss.Identifier
	Msgs      []tss.Message
}

func (m MessagePacket) String() string {
	return fmt.Sprintf("packet-%d%s", m.Round, formatMsgs(m.Msgs))
}

func formatMsgs(msgs []tss.Message) string {
	var s strings.Builder
	s.WriteString("[")
	for _, msg := range msgs {
		s.WriteString(fmt.Sprintf("msg<%d-%d>,", msg.From, msg.To))
	}
	s.WriteString("]")
	return s.String()
}
