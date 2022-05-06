// SPDX-License-Identifier: MIT

//use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
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
pub enum TaskStatsAttrs {
    Pid(u32),
    TGid(u32),
    RegisterCPUMask(String),
    DeRegisterCPUMask(String),
}

impl Nla for TaskStatsAttrs {
    fn value_len(&self) -> usize {
        use TaskStatsAttrs::*;
        match self {
            Pid(v) => size_of_val(v),
            TGid(v) => size_of_val(v),
            RegisterCPUMask(s) => s.len() + 1,
            DeRegisterCPUMask(s) => s.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        use TaskStatsAttrs::*;
        match self {
            Pid(_) => TASKSTATS_CMD_ATTR_PID,
            TGid(_) => TASKSTATS_CMD_ATTR_TGID,
            RegisterCPUMask(_) => TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
            DeRegisterCPUMask(_) => TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use TaskStatsAttrs::*;
        match self {
            Pid(v) => NativeEndian::write_u32(buffer, *v),
            TGid(v) => NativeEndian::write_u32(buffer, *v),
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

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TaskStatsAttrs {
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
