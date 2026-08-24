#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: shared http1-module state
//
// Description: Buffer shared by the HTTP/1 response encoders
//   (http1_write_response, reply_status). The status-line strings and
//   status_table live in find_http_code.S (their only consumer); the
//   content-* header strings live in http1_write_response.S and the
//   error-page strings in reply_status.S. Length constants that are
//   needed as immediates across files live in defs.S.
//
// Exported Symbols:
//   header_buf — scratch the HTTP/1 encoder builds the header in
// ─────────────────────────────────────────────────────────────────────

.bss
.align 4
.equ header_buf_size, RESPONSE_HEADER_SIZE
OBJECT header_buf
              .skip header_buf_size
ENDOBJ header_buf

