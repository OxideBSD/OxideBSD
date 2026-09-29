//! The kernel proper, in the BSDs' sense: the socket layer and local sockets (`uipc_*`) and the
//! sysctl tree (`kern_sysctl`), the message buffer (`subr_msgbuf`).

pub mod kern_sysctl;
pub mod subr_msgbuf;
pub mod uipc_socket;
pub mod uipc_usrreq;
