// SPDX-License-Identifier: MIT

//! Generic netlink controller implementation
//!
//! This module provides the definition of the taskstats packet.

use self::nlas::*;
use crate::{traits::*, GenlHeader};
use anyhow::Context;
use netlink_packet_utils::{nla::NlasIterator, traits::*, DecodeError};
use std::convert::{TryFrom, TryInto};

/// Netlink attributes for this family
pub mod nlas;

/// Command code definition 
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStatsCmds {
    /// user->kernel request/get-response
	Get,
    /// kernel->user event
	New,
}

pub const TASKSTATS_CMD_GET: u8 = 1;
pub const TASKSTATS_CMD_NEW: u8 = 2;

impl From<TaskStatsCmds> for u8 {
    fn from(cmd: TaskStatsCmds) -> u8 {
        use TaskStatsCmds::*;
        match cmd {
            Get => TASKSTATS_CMD_GET,
            New => TASKSTATS_CMD_NEW,
        }
    }
}

impl TryFrom<u8> for TaskStatsCmds {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use TaskStatsCmds::*;
        Ok(match value {
            TASKSTATS_CMD_GET => Get,
            TASKSTATS_CMD_NEW => New,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unknown taskstat command: {}",
                    cmd
                )))
            }
        })
    }
}


/// Payload of taskstats
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskStatsCmd {
    /// Command code of this message
    pub cmd: TaskStatsCmds,
    /// Netlink attributes in this message
    pub nlas: Vec<TaskStatsCmdAttrs>,
    /// family id is not fixed
    pub family_id: u16
}

impl GenlFamily for TaskStatsCmd {
    fn family_name() -> &'static str {
        "taskstats"
    }

    fn family_id(&self) -> u16 {
        self.family_id
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        1
    }
}

impl Emitable for TaskStatsCmd {
    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for TaskStatsCmd {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(TaskStatsCmd {
            cmd: header.cmd.try_into()?,
            nlas: parse_taskstat_nlas(buf)?,
            // the family is kind of dynamic, it
            // must be set after parsing
            family_id: 0
        })
    }
}

fn parse_taskstat_nlas(buf: &[u8]) -> Result<Vec<TaskStatsCmdAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| TaskStatsCmdAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse control message attributes")?;

    Ok(nlas)
}
