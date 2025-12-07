use std::{collections::HashMap, ffi::c_void, io, os::fd::RawFd};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::tcp::{TcpFamily, internal::SocketStatus};

pub struct PacketReactor {
    epoll_fd: Option<RawFd>,
    mmap: (*mut c_void, usize),
    pending: HashMap<u64, DispatchedFrame>,
    receiver: Receiver<DispatchedFrame>,
    sender_for_dispacher: Option<Sender<DispatchedFrame>>,
}

pub enum PacketReactorMode {
    OnDemand,
    Background,
}

impl Default for PacketReactorMode {
    fn default() -> Self {
        Self::OnDemand
    }
}

pub(crate) struct Dispatcher {
    pub inner: Sender<DispatchedFrame>,
}

impl Dispatcher {
    pub async fn send(&mut self, frame: DispatchedFrame) {
        self.inner.send(frame).await.ok();
    }
}

pub(crate) struct DispatchedFrame {
    pub sender: Option<tokio::sync::oneshot::Sender<SocketStatus>>,
    pub tcp_family: TcpFamily,
    pub dst_addr: [u8; 4],
    pub dst_port: u16,
    pub seq_number: u32,
}

impl PacketReactor {
    pub fn new(
        _socket_fd: RawFd,
        mmap: (*mut c_void, usize),
        mode: PacketReactorMode,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            match mode {
                PacketReactorMode::OnDemand => {
                    let (tx, rx) = tokio::sync::mpsc::channel::<DispatchedFrame>(1024);
                    io::Result::Ok(PacketReactor {
                        epoll_fd: None,
                        pending: HashMap::new(),
                        mmap: mmap,
                        receiver: rx,
                        sender_for_dispacher: Some(tx),
                    })
                }
                PacketReactorMode::Background => {
                    unimplemented!();
                    // let epoll_fd = unsafe { libc::epoll_create1(0) };
                    // if epoll_fd < 0 {
                    //     return Err(io::Error::last_os_error());
                    // }
                    //
                    // let mut event = libc::epoll_event {
                    //     events: libc::EPOLLIN as u32,
                    //     u64: socket_fd as u64,
                    // };
                    //
                    // if unsafe {
                    //     libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, socket_fd, &mut event)
                    // } < 0
                    // {
                    //     unsafe { libc::close(epoll_fd) };
                    //     return Err(io::Error::last_os_error());
                    // }
                    //
                    // let (tx, rx) = tokio::sync::mpsc::channel::<DispatchedFrame>(1024);
                    // io::Result::Ok(PacketReactor {
                    //     epoll_fd: Some(epoll_fd),
                    //     mmap: mmap,
                    //     queue: VecDeque::new(),
                    //     receiver: rx,
                    //     sender_for_dispacher: Some(tx),
                    // })
                }
            }
        }
    }

    pub(crate) fn get_raw_dispatcher(&mut self) -> Sender<DispatchedFrame> {
        self.sender_for_dispacher.take().unwrap()
    }

    pub async fn run(&mut self) {
        #[cfg(target_os = "linux")]
        {
            loop {
                match self.epoll_fd {
                    // Background mode
                    Some(_e) => {
                        unimplemented!("The runtime reactor option is not implemented yet");
                        // while let Ok(f) = self.receiver.try_recv() {
                        //     self.queue
                        //         .push_back(DispatchedFrameFuture::new(self.epoll_fd, f));
                        // }

                        // let mut ev = libc::epoll_event { events: 0, u64: 0 };
                        // let r = unsafe { libc::epoll_wait(self.epoll_fd, &mut ev, 1, 0) };
                        //
                        // if r > 0 {
                        //     // read mmap
                        // }

                        // match self.queue.pop_front() {
                        //     Some(mut p) => {
                        //         let sender = p.dispatched_frame.sender.take();
                        //         let r = p.await;
                        //
                        //         sender.unwrap().send(r).ok();
                        //     }
                        //     None => continue,
                        // }
                    }
                    // On demand mode
                    None => {
                        use crate::sys::linux::TP_BLOCK_NR;
                        use crate::sys::linux::TP_BLOCK_SIZE;

                        while let Ok(f) = self.receiver.try_recv() {
                            let mut addr: u32 = 0;
                            for o in f.dst_addr {
                                addr |= o as u32;
                            }
                            let key: u64 = (f.seq_number | addr | f.dst_port as u32) as u64;
                            self.pending.insert(key, f);
                        }
                        self.pending.shrink_to_fit();

                        let (mmap_ptr, _ptr_len) = self.mmap;

                        // Run ring and find corresponding frames
                        for block_idx in 0..TP_BLOCK_NR {
                            let block_ptr = unsafe {
                                (mmap_ptr as *mut u8).add((block_idx * TP_BLOCK_SIZE) as usize)
                                    as *mut libc::tpacket_block_desc
                            };

                            let block = unsafe { &mut *block_ptr };
                            let hdr = unsafe { &mut block.hdr.bh1 };

                            if hdr.block_status != libc::TP_STATUS_USER {
                                continue;
                            }

                            let num_frames = hdr.num_pkts;
                            let mut offset = hdr.offset_to_first_pkt as usize;

                            for _ in 0..num_frames {
                                let frame_ptr = unsafe {
                                    (block_ptr as *mut u8).add(offset) as *mut libc::tpacket3_hdr
                                };
                                let frame = unsafe { &mut *frame_ptr };

                                let data_ptr =
                                    unsafe { (frame_ptr as *mut u8).add(frame.tp_mac as usize) };
                                let data = unsafe {
                                    std::slice::from_raw_parts(data_ptr, frame.tp_len as usize)
                                };

                                self.process_frame(data, &frame);

                                if frame.tp_next_offset == 0 {
                                    break;
                                }

                                offset += frame.tp_next_offset as usize;
                            }

                            // return block to the kernel
                            hdr.block_status = libc::TP_STATUS_KERNEL;
                        }
                    }
                }
            }
        }
    }

    fn process_frame(&mut self, data: &[u8], hdr: &libc::tpacket3_hdr) {
        todo!()
        // TODO: generate "key" from `data`, verify if it exists in `self.pending`, if so check
        // TcpFamily in the `DispatchedFrame` we got from the `self.pending` and check accordingly
        // for the tcp handshake logic we want.
    }
}

impl Drop for PacketReactor {
    fn drop(&mut self) {
        let (mmap, ptr_len) = self.mmap;
        let res = unsafe { libc::munmap(mmap, ptr_len) };
        if res != 0 {
            eprintln!("Failed to remove any mappings from the adress space");
        }
    }
}
