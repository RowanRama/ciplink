//! The jobs of a session's queue, and how the reads of several callers are merged into one read and split
//! back. Pure functions, no I/O.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::handle::Completer;
use super::subscribe::SubShared;
use crate::cip::TagResult;
use crate::{Error, Result, Value};

/// A closure run on the session thread with the protocol state, or with the error that keeps it from running.
/// It returns its error and the completion of its handle, which runs once the queue's state is updated.
pub(crate) type CallFn<P> =
    Box<dyn FnOnce(Result<&mut P>) -> (Option<Error>, Box<dyn FnOnce()>) + Send>;

/// One request in a session's queue.
pub(crate) enum Job<P> {
    /// A caller's read.
    Read {
        tags: Vec<String>,
        done: Completer<Vec<TagResult>>,
    },
    /// A subscription's read; packed like a Read.
    Poll { sub: Arc<SubShared> },
    /// A caller's write: never merged, never reordered.
    Write {
        items: Vec<(String, Value)>,
        done: Completer<Vec<TagResult>>,
    },
    /// The user's `open()`.
    Open { done: Completer<bool> },
    /// Anything else.
    Call(CallFn<P>),
}

impl<P> Job<P> {
    /// True for a Read or a Poll, which can be merged with the reads next to it.
    pub(crate) fn is_read(&self) -> bool {
        matches!(self, Job::Read { .. } | Job::Poll { .. })
    }

    /// True for the jobs that fail fast while reconnecting: reads, writes and polls.
    pub(crate) fn needs_link(&self) -> bool {
        matches!(
            self,
            Job::Read { .. } | Job::Write { .. } | Job::Poll { .. }
        )
    }

    /// Completes the job with `error` without running it (a poll just ends; its subscription is told
    /// separately).
    pub(crate) fn fail(self, error: Error) {
        match self {
            Job::Read { done, .. } | Job::Write { done, .. } => done.complete(Err(error)),
            Job::Open { done } => done.complete(Err(error)),
            Job::Poll { sub } => sub.poll_done(),
            Job::Call(f) => f(Err(error)).1(),
        }
    }
}

/// The jobs the session thread runs next: every Read or Poll at the head of the queue up to the first other
/// job, or that one other job alone.
pub(crate) fn take_batch<P>(jobs: &mut VecDeque<Job<P>>) -> Vec<Job<P>> {
    let mut batch = Vec::new();
    while jobs.front().is_some_and(Job::is_read) {
        batch.extend(jobs.pop_front());
    }
    if batch.is_empty() {
        batch.extend(jobs.pop_front());
    }
    batch
}

/// The tag list read for several callers, and where each caller's tags are in it. The first list goes in
/// unchanged (duplicates included); a later caller's tag already in the list reuses its first position.
pub(crate) fn merge_reads(lists: &[&[String]]) -> (Vec<String>, Vec<Vec<usize>>) {
    let total = lists.iter().map(|l| l.len()).sum();
    let mut merged: Vec<String> = Vec::with_capacity(total);
    let mut first: HashMap<String, usize> = HashMap::with_capacity(total);
    let mut positions = Vec::with_capacity(lists.len());
    for (n, list) in lists.iter().enumerate() {
        let mut at = Vec::with_capacity(list.len());
        for tag in list.iter() {
            let reuse = if n == 0 {
                None
            } else {
                first.get(tag).copied()
            };
            let i = match reuse {
                Some(i) => i,
                None => {
                    merged.push(tag.clone());
                    let i = merged.len() - 1;
                    first.entry(tag.clone()).or_insert(i);
                    i
                }
            };
            at.push(i);
        }
        positions.push(at);
    }
    (merged, positions)
}

/// Each caller's results (cloned from `results` by position), or each caller the same error.
pub(crate) fn split_reads(
    results: Result<Vec<TagResult>>,
    positions: &[Vec<usize>],
) -> Vec<Result<Vec<TagResult>>> {
    match results {
        Ok(results) => positions
            .iter()
            .map(|at| {
                at.iter()
                    .map(|&i| {
                        results
                            .get(i)
                            .cloned()
                            .ok_or_else(|| Error::data("a merged read returned too few results"))
                    })
                    .collect()
            })
            .collect(),
        Err(err) => positions.iter().map(|_| Err(err.clone())).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::dispatch::Dispatcher;
    use crate::session::handle::Handle;

    fn strings(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|t| (*t).to_owned()).collect()
    }

    fn read(tags: &[&str]) -> Job<()> {
        let (_, done) = Handle::new(Dispatcher::default());
        Job::Read {
            tags: strings(tags),
            done,
        }
    }

    fn write() -> Job<()> {
        let (_, done) = Handle::new(Dispatcher::default());
        Job::Write {
            items: vec![("w".into(), Value::DInt(1))],
            done,
        }
    }

    fn kinds(jobs: &[Job<()>]) -> String {
        jobs.iter()
            .map(|j| match j {
                Job::Read { .. } => 'r',
                Job::Poll { .. } => 'p',
                Job::Write { .. } => 'w',
                Job::Open { .. } => 'o',
                Job::Call(_) => 'c',
            })
            .collect()
    }

    fn result(tag: &str) -> TagResult {
        TagResult {
            tag: tag.into(),
            value: Some(Value::DInt(tag.len() as i32)),
            data_type: Some("DINT".into()),
            error: None,
        }
    }

    #[test]
    fn take_batch_takes_reads_up_to_a_write() {
        let mut q: VecDeque<_> = [read(&["a"]), read(&["b"]), write(), read(&["c"])].into();
        assert_eq!(kinds(&take_batch(&mut q)), "rr");
        assert_eq!(kinds(&take_batch(&mut q)), "w");
        assert_eq!(kinds(&take_batch(&mut q)), "r");
        assert!(take_batch(&mut q).is_empty());
    }

    #[test]
    fn take_batch_takes_one_non_read() {
        let mut q: VecDeque<_> = [write(), write(), read(&["a"])].into();
        assert_eq!(kinds(&take_batch(&mut q)), "w");
        assert_eq!(kinds(&take_batch(&mut q)), "w");
        assert_eq!(kinds(&take_batch(&mut q)), "r");
    }

    #[test]
    fn merge_keeps_the_first_list_verbatim() {
        let first = strings(&["a", "b", "a"]);
        let (merged, at) = merge_reads(&[&first]);
        assert_eq!(merged, first);
        assert_eq!(at, [vec![0, 1, 2]]);
    }

    #[test]
    fn merge_reads_a_tag_once_for_two_callers() {
        let (a, b, c) = (
            strings(&["a", "b", "a"]),
            strings(&["b", "c"]),
            strings(&["c", "d"]),
        );
        let (merged, at) = merge_reads(&[&a, &b, &c]);
        assert_eq!(merged, ["a", "b", "a", "c", "d"]);
        assert_eq!(at, [vec![0, 1, 2], vec![1, 3], vec![3, 4]]);
    }

    #[test]
    fn split_gives_each_caller_its_positions() {
        let results = Ok(vec![result("a"), result("bb"), result("ccc")]);
        let split = split_reads(results, &[vec![0, 1], vec![1, 2], vec![]]);
        assert_eq!(split[0], Ok(vec![result("a"), result("bb")]));
        assert_eq!(split[1], Ok(vec![result("bb"), result("ccc")]));
        assert_eq!(split[2], Ok(vec![]));
    }

    #[test]
    fn split_gives_every_caller_the_error() {
        let split = split_reads(Err(Error::comm("lost")), &[vec![0], vec![0, 1]]);
        assert_eq!(
            split,
            vec![Err(Error::comm("lost")), Err(Error::comm("lost"))]
        );
    }
}
