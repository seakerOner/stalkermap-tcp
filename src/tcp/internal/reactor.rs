use std::{collections::VecDeque, io, os::fd::RawFd};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::tcp::{
    TcpFamily,
    internal::{PacketFrame, SocketStatus},
};

pub struct PacketReactor {
    epoll_fd: RawFd,
    queue: VecDeque<DispatchedFrame>,
    receiver: Receiver<DispatchedFrame>,
    sender_for_dispacher: Sender<DispatchedFrame>,
}

pub struct Dispatcher {
    inner: Sender<DispatchedFrame>,
}

impl Dispatcher {
    pub async fn send(&mut self, frame: DispatchedFrame) {
        self.inner.send(frame).await;
    }
}

pub(crate) struct DispatchedFrame {
    pub sender: tokio::sync::oneshot::Sender<SocketStatus>,
    pub tcp_family: TcpFamily,
    pub dst_addr: [u8; 4],
    pub dst_port: u16,
    pub seq_number: u32,
}

impl PacketReactor {
    pub fn new(socket_fd: RawFd) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let epoll_fd = unsafe { libc::epoll_create1(0) };
            if epoll_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: socket_fd as u64,
            };

            if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, socket_fd, &mut event) } < 0
            {
                unsafe { libc::close(epoll_fd) };
                return Err(io::Error::last_os_error());
            }

            let (tx, rx) = tokio::sync::mpsc::channel::<DispatchedFrame>(1024);
            io::Result::Ok(PacketReactor {
                epoll_fd: epoll_fd,
                queue: VecDeque::new(),
                receiver: rx,
                sender_for_dispacher: tx,
            })
        }
    }

    pub fn get_dispatcher(&self) -> Dispatcher {
        Dispatcher {
            inner: self.sender_for_dispacher.clone(),
        }
    }

    pub async fn run(&mut self) {
        #[cfg(target_os = "linux")]
        {
            loop {
                match self.receiver.try_recv() {
                    Ok(f) => {
                        self.queue.push_back(f);
                    }
                    Err(e) => match e {
                        tokio::sync::mpsc::error::TryRecvError::Empty => continue,
                        tokio::sync::mpsc::error::TryRecvError::Disconnected => break,
                    },
                }

                match self.queue.pop_front() {
                    Some(p) => {
                        let fut = DispatchedFrameFuture {
                            epoll_fd: self.epoll_fd,
                            dispatched_frame: &p,
                        };
                        let r = fut.await;

                        p.sender.send(r).ok();
                    }
                    None => continue,
                }
            }
        }
    }
}

pub(crate) struct DispatchedFrameFuture<'a> {
    epoll_fd: RawFd,
    dispatched_frame: &'a DispatchedFrame,
}

impl<'a> Future for DispatchedFrameFuture<'a> {
    type Output = SocketStatus;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        #[cfg(target_os = "linux")]
        {
            // TODO: Make the poll get the status of the dispatched frame

            // let mut ev = libc::epoll_event { events: 0, u64: 0 };
            // let r = unsafe { libc::epoll_wait(self.epoll_fd, &mut ev, 1, 0) };
            //
            // if r == 0 {
            //     cx.waker().wake_by_ref();
            //     return std::task::Poll::Pending;
            // }
            //
            // std::task::Poll::Ready(Ok(()))
            std::task::Poll::Ready(SocketStatus::Open)
        }
    }
}

impl<'a> Drop for DispatchedFrameFuture<'a> {
    fn drop(&mut self) {
        unsafe { libc::close(self.epoll_fd) };
    }
}
