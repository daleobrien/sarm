#include "../defs.S"

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
//   x0, x9, x16 (syscall scratch)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC child_end
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
