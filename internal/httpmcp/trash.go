package httpmcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// TrashRefused reports whether an HTTP mail_trash must stop before
// the approval cache and before any Proton call. A missing mirror
// row, or a message already in Trash, is refused. This function
// itself does not call Proton.
func TrashRefused(ctx context.Context, st *store.Store, args json.RawMessage) error {
	var in struct {
		MessageID string `json:"message_id"`
	}
	_ = json.Unmarshal(args, &in)
	if st == nil || strings.TrimSpace(in.MessageID) == "" {
		return errors.New("mail_trash refused: the mirror cannot say whether this message is already in Trash")
	}
	m, err := st.GetMessage(ctx, in.MessageID)
	if err != nil {
		return errors.New("mail_trash refused: the mirror cannot say whether this message is already in Trash")
	}
	if strings.EqualFold(m.Folder, "trash") {
		return errors.New("mail_trash refused: the message is already in Trash")
	}
	return nil
}
