//! The kernel proper, in the BSDs' sense: for now the socket layer and local sockets (`uipc_*`).

pub mod uipc_socket;
pub mod uipc_usrreq;
