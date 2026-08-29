#include "../defs.S"

.extern transport_flush

// ─────────────────────────────────────────────────────────────────────
// Function Name: child_end
//
// Description: End of connection handling. Closes the client socket,
//   closes file_des if it's open, and then exits — this is a forked
//   child, one process per connection, and the parent's accept loop is
//   what takes the next one. In the no_fork debug mode there is no
//   child, so it loops back to accept instead.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   (never returns — exits the child, or branches to loop under no_fork)
//
// Clobbered Registers:
//   x0-x17, x19-x26, x30, v0-v7, v16-v30 — the syscall scratch this
//   always used (x0, x9, x16) plus everything transport_flush reaches
//   through transport_write_now. Nothing here has to be preserved:
//   child_end exits the process (or, under no_fork, branches to the
//   accept loop, which starts a connection from scratch).
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC child_end
    // Anything transport_write has staged goes out before the socket
    // does. h2_connection_loop already flushes on its own way out, so
    // this is normally a load and a branch over an empty stage — but
    // losing a response to a close(2) is the one failure this staging
    // could introduce, and this is the single funnel every connection
    // leaves through, so it is worth the two instructions.
    ldr_l x0, clientfd
    bl transport_flush

    // close(clientfd)
    SCWINUM SYS_close
    ldr_l x0, clientfd
    SCWISVC
    SCERR

    ldr_l x0, file_des
    cmn x0, #1
    b.eq 1f
    SCWINUM SYS_close
    // x0 is set
    SCWISVC
    SCERR
1:
    // A forked child serves exactly one connection, so it exits here and
    // the parent's accept loop carries on. Only the debug no-fork mode
    // still loops back to accept the next connection in this process.
    ldr_l x0, no_fork
    cbnz x0, 2f
    SCWINUM SYS_exit
    mov x0, #0
    SCWISVC
    SCERR
2:
    b loop
ENDFUNC child_end
