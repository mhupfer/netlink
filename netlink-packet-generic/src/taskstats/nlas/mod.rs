// SPDX-License-Identifier: MIT

//use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian as ne};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::mem::size_of_val;

pub const TASKSTATS_CMD_ATTR_PID: u16 = 1;
pub const TASKSTATS_CMD_ATTR_TGID: u16 = 2;
pub const TASKSTATS_CMD_ATTR_REGISTER_CPUMASK: u16 = 3;
pub const TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK: u16 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskStatsCmdAttrs {
    Pid(u32),
    TGid(u32),
    RegisterCPUMask(String),
    DeRegisterCPUMask(String),
}

impl Nla for TaskStatsCmdAttrs {
    fn value_len(&self) -> usize {
        use TaskStatsCmdAttrs::*;
        match self {
            Pid(v) => size_of_val(v),
            TGid(v) => size_of_val(v),
            RegisterCPUMask(s) => s.len() + 1,
            DeRegisterCPUMask(s) => s.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        use TaskStatsCmdAttrs::*;
        match self {
            Pid(_) => TASKSTATS_CMD_ATTR_PID,
            TGid(_) => TASKSTATS_CMD_ATTR_TGID,
            RegisterCPUMask(_) => TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
            DeRegisterCPUMask(_) => TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use TaskStatsCmdAttrs::*;
        match self {
            Pid(v) => ne::write_u32(buffer, *v),
            TGid(v) => ne::write_u32(buffer, *v),
            RegisterCPUMask(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            DeRegisterCPUMask(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TaskStatsCmdAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_CMD_ATTR_REGISTER_CPUMASK => Self::RegisterCPUMask(
                parse_string(payload).context("invalid TASKSTATS_CMD_ATTR_REGISTER_CPUMASK value")?,
            ),
            TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK => Self::DeRegisterCPUMask(
                parse_string(payload).context("invalid TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK value")?,
            ),
            TASKSTATS_CMD_ATTR_PID => {
                Self::Pid(parse_u32(payload).context("invalid TASKSTATS_CMD_ATTR_PID value")?)
            }
            TASKSTATS_CMD_ATTR_TGID => {
                Self::TGid(parse_u32(payload).context("invalid TASKSTATS_CMD_ATTR_TGID value")?)
            }
            kind => return Err(DecodeError::from(format!("Unknown NLA type: {}", kind))),
        })
    }
}

/*-------------------- Taskstats Events --------------------*/


/// Event code definition 
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStatsEventAttrs {
    /// process id
	Pid(i32),
    /// Thread group id
	TGid(i32),
    /// taskstats structure
    Stats(Statistics),
    /// contains pid + stats
    AggrPid,
    /// contains tgid + stats
    AggrTid,
    /// contains nothing
    Null
}

const TASKSTATS_TYPE_PID:u16 = 1;		/* Process id */
const TASKSTATS_TYPE_TGID:u16 = 2;		/* Thread group id */
const TASKSTATS_TYPE_STATS:u16 = 3;		/* taskstats structure */
const TASKSTATS_TYPE_AGGR_PID:u16 = 4;	/* contains pid + stats */
const TASKSTATS_TYPE_AGGR_TGID:u16 = 5;	/* contains tgid + stats */
const TASKSTATS_TYPE_NULL:u16 = 6;		/* contains nothing */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
///the actual struct containing statistics
pub struct Statistics
{
    pub version: u16,
    pub ac_exitcode: u32,
    pub ac_flag: u8,
    pub ac_nice: u8,
    pub cpu_count: u64,
    pub cpu_delay_total: u64,
    pub blkio_count: u64,
    pub blkio_delay_total: u64,
    pub swapin_count: u64,
    pub swapin_delay_total: u64,
    pub cpu_run_real_total: u64,
    pub cpu_run_virtual_total: u64,
    pub ac_comm: [u8; 32usize],
    pub ac_sched: u8,
    pub ac_pad: [u8; 3usize],
    pub __bindgen_padding_0: u32,
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,
    pub ac_etime: u64,
    pub ac_utime: u64,
    pub ac_stime: u64,
    pub ac_minflt: u64,
    pub ac_majflt: u64,
    pub coremem: u64,
    pub virtmem: u64,
    pub hiwater_rss: u64,
    pub hiwater_vm: u64,
    pub read_char: u64,
    pub write_char: u64,
    pub read_syscalls: u64,
    pub write_syscalls: u64,
    #[cfg(feature = "IO_ACCOUNTING")]
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
    pub nvcsw: u64,
    pub nivcsw: u64,
    pub ac_utimescaled: u64,
    pub ac_stimescaled: u64,
    pub cpu_scaled_run_real_total: u64,
    pub freepages_count: u64,
    pub freepages_delay_total: u64,
    pub thrashing_count: u64,
    pub thrashing_delay_total: u64,
}


// impl Nla for TaskStatsEventAttrs {
//     fn value_len(&self) -> usize {
//         use TaskStatsEventAttrs::*;
//         match self {
//             Pid(v) => size_of_val(v),
//             TGid(v) => size_of_val(v),
//             AggrPid => 0,
//             AggrTid => 0,
//             Null => 0,
//             Stats(x) => std::mem::size_of::<Statistics>()
//         }
//     }

//     fn kind(&self) -> u16 {
//         use TaskStatsEventAttrs::*;
//         match self {
//             Pid(v) => TASKSTATS_TYPE_PID,
//             TGid(v) => TASKSTATS_TYPE_TGID,
//             AggrPid => TASKSTATS_TYPE_AGGR_PID,
//             AggrTid => TASKSTATS_TYPE_AGGR_TGID,
//             Null => TASKSTATS_TYPE_NULL,
//             Stats(x) => TASKSTATS_TYPE_STATS
//         }
//     }

//     fn emit_value(&self, buffer: &mut [u8]) {
//         use TaskStatsEventAttrs::*;
//         match self {
//             Pid(v) => ne::write_i32(buffer, *v),
//             TGid(v) => ne::write_i32(buffer, *v),
//             Stats(x) => x.emit(buffer)
//             _ => ()
//         }
//     }
// }


// impl Emitable for Statistics {
//     fn buffer_len(&self) -> usize {
//         std::mem::size_of::<Self>()
//     }

//     fn emit(&self, buffer: &mut [u8]) {
//         ne::write_u16(&mut buffer[0..2], self.version),
//         ne::write_u16(&mut buffer[2..6], self.ac_exitcode);
//     }
// }

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TaskStatsEventAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_TYPE_STATS => Self::Stats(
                Statistics::parse(&payload).context("invalid TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK value")?,
            ),
            TASKSTATS_TYPE_PID => {
                Self::Pid(parse_i32(payload).context("invalid TASKSTATS_CMD_ATTR_PID value")?)
            }
            TASKSTATS_TYPE_TGID => {
                Self::TGid(parse_i32(payload).context("invalid TASKSTATS_CMD_ATTR_TGID value")?)
            }
            TASKSTATS_TYPE_AGGR_PID => Self::AggrPid,
            TASKSTATS_TYPE_AGGR_TGID => Self::AggrTid,
            TASKSTATS_TYPE_NULL => Self::Null,
            kind => return Err(DecodeError::from(format!("Unknown NLA type: {}", kind))),
        })
    }
}



/****************************/
/* _read_u8        		*/
/****************************/
fn _read_u8(buf: &[u8], offs: &mut usize) -> u8
{
    let res = buf[*offs];
    *offs += 1;
    res
}


/****************************/
/* _read_u16        		*/
/****************************/
fn _read_u16(buf: &[u8], offs: &mut usize) -> u16
{
    let res = ne::read_u16(&buf[*offs..*offs+2]);
    *offs += 2;
    res
}


/****************************/
/* _read_u32        		*/
/****************************/
fn _read_u32(buf: &[u8], offs: &mut usize) -> u32
{
    let res = ne::read_u32(&buf[*offs..*offs+4]);
    *offs += 4;
    res
}


/****************************/
/* _read_u64        		*/
/****************************/
fn _read_u64(buf: &[u8], offs: &mut usize) -> u64
{
    let res = ne::read_u64(&buf[*offs..*offs+8]);
    *offs += 8;
    res
}


/****************************/
/* cp_u8 		        	*/
/****************************/
fn cp_u8(src: &[u8], src_offset: usize, dest: &mut [u8], len: usize) -> usize
{
    dest.copy_from_slice(&src[src_offset..src_offset + len]);
    dest.len()
}

/************************************************/
/* ParseableParametrized for ConnectorResponse	*/
/************************************************/
impl Parseable<[u8]> for Statistics {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError>
    {
        let mut offs = 0;
        let ac_pad_offs;
        let ac_comm_offs;

        let mut s = Statistics{
            version: _read_u16(buf, &mut offs),
            ac_exitcode: _read_u32(buf, &mut offs),
            ac_flag: _read_u8(buf, &mut offs),
            ac_nice: _read_u8(buf, &mut offs),
            cpu_count: _read_u64(buf, &mut offs),
            cpu_delay_total: _read_u64(buf, &mut offs),
            blkio_count: _read_u64(buf, &mut offs),
            blkio_delay_total: _read_u64(buf, &mut offs),
            swapin_count: _read_u64(buf, &mut offs),
            swapin_delay_total: _read_u64(buf, &mut offs),
            cpu_run_real_total: _read_u64(buf, &mut offs),
            cpu_run_virtual_total: _read_u64(buf, &mut offs),
            ac_comm: {ac_comm_offs = offs; [0; 32]},
            ac_sched: _read_u8(buf, &mut offs),
            ac_pad: {ac_pad_offs = offs; [0; 3]},
            __bindgen_padding_0: _read_u32(buf, &mut offs),
            ac_uid: _read_u32(buf, &mut offs),
            ac_gid: _read_u32(buf, &mut offs),
            ac_pid: _read_u32(buf, &mut offs),
            ac_ppid: _read_u32(buf, &mut offs),
            ac_btime: _read_u32(buf, &mut offs),
            ac_etime: _read_u64(buf, &mut offs),
            ac_utime: _read_u64(buf, &mut offs),
            ac_stime: _read_u64(buf, &mut offs),
            ac_minflt: _read_u64(buf, &mut offs),
            ac_majflt: _read_u64(buf, &mut offs),
            coremem: _read_u64(buf, &mut offs),
            virtmem: _read_u64(buf, &mut offs),
            hiwater_rss: _read_u64(buf, &mut offs),
            hiwater_vm: _read_u64(buf, &mut offs),
            read_char: _read_u64(buf, &mut offs),
            write_char: _read_u64(buf, &mut offs),
            read_syscalls: _read_u64(buf, &mut offs),
            write_syscalls: _read_u64(buf, &mut offs),
            #[cfg(feature = "IO_ACCOUNTING")]
            read_bytes: _read_u64(buf, &mut offs),
            write_bytes: _read_u64(buf, &mut offs),
            cancelled_write_bytes: _read_u64(buf, &mut offs),
            nvcsw: _read_u64(buf, &mut offs),
            nivcsw: _read_u64(buf, &mut offs),
            ac_utimescaled: _read_u64(buf, &mut offs),
            ac_stimescaled: _read_u64(buf, &mut offs),
            cpu_scaled_run_real_total: _read_u64(buf, &mut offs),
            freepages_count: _read_u64(buf, &mut offs),
            freepages_delay_total: _read_u64(buf, &mut offs),
            thrashing_count: _read_u64(buf, &mut offs),
            thrashing_delay_total: _read_u64(buf, &mut offs),
        };

        cp_u8(&buf, ac_comm_offs, &mut s.ac_comm, 3);
        cp_u8(&buf, ac_pad_offs, &mut s.ac_pad, 3);
        Ok(s)
    }
}
