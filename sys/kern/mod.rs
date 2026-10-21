//! The kernel proper, in the BSDs' sense: the socket layer and local sockets (`uipc_*`) and the
//! sysctl tree (`kern_sysctl`), the load average (`kern_synch`), the message buffer (`subr_msgbuf`).

pub mod fsconf;
pub mod kern_core;
pub mod kern_descrip;
pub mod kern_kthread;
pub mod kern_procctl;
pub mod kern_synch;
pub mod kern_sysctl;
pub mod subr_msgbuf;
pub mod subr_uio;
pub mod uipc_socket;
pub mod uipc_usrreq;
pub mod vfs_bdev;
pub mod vfs_advlock;
pub mod vfs_bio;
pub mod vfs_cache;
pub mod vfs_dead;
pub mod vfs_lookup;
pub mod vfs_mount;
pub mod vfs_subr;
pub mod vfs_syscalls;
pub mod vfs_vnops;
pub mod vnode_if;
