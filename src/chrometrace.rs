use std::cmp::min;
use std::collections::HashMap;
use std::io::BufWriter;
use std::io::Seek;
use std::io::Write;
use std::time::Instant;

use anyhow::Error;
use flate2::write::GzEncoder;
use serde_derive::Serialize;
use tempfile::NamedTempFile;

use crate::stack_trace::Frame;
use crate::stack_trace::StackTrace;

#[derive(Clone, Debug, Serialize)]
struct Args {
    pub filename: String,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
struct Event {
    pub args: Args,
    pub cat: String,
    pub name: String,
    pub ph: String,
    pub pid: u64,
    pub tid: u64,
    pub ts: u64,
}

struct Writer {
    file: GzEncoder<BufWriter<NamedTempFile>>,
    first: bool,
}

impl Writer {
    fn new() -> std::io::Result<Self> {
        let mut file = GzEncoder::new(
            BufWriter::new(NamedTempFile::new()?),
            flate2::Compression::default(),
        );
        write!(file, "[")?;
        Ok(Writer { file, first: true })
    }

    fn write(&mut self, event: Event) -> Result<(), Error> {
        if self.first {
            self.first = false;
        } else {
            write!(self.file, ",")?;
        }
        write!(self.file, "{}", serde_json::to_string(&event)?)?;
        Ok(())
    }

    fn close(mut self) -> Result<NamedTempFile, Error> {
        writeln!(self.file, "]")?;
        Ok(self.file.finish()?.into_inner()?)
    }
}

pub struct Chrometrace {
    writer: Writer,
    start_ts: Instant,
    prev_traces: HashMap<u64, StackTrace>,
    show_linenumbers: bool,
}

impl Chrometrace {
    pub fn new(show_linenumbers: bool) -> Result<Chrometrace, Error> {
        Ok(Chrometrace {
            writer: Writer::new()?,
            start_ts: Instant::now(),
            prev_traces: HashMap::new(),
            show_linenumbers,
        })
    }

    // Return whether these frames are similar enough such that we should merge
    // them, instead of creating separate events for them.
    fn should_merge_frames(&self, a: &Frame, b: &Frame) -> bool {
        a.name == b.name && a.filename == b.filename && (!self.show_linenumbers || a.line == b.line)
    }

    fn event(&self, trace: &StackTrace, frame: &Frame, phase: &str, ts: u64) -> Event {
        Event {
            tid: trace.thread_id,
            pid: trace.pid as u64,
            name: frame.name.to_string(),
            cat: "py-spy".to_owned(),
            ph: phase.to_owned(),
            ts,
            args: Args {
                filename: frame.filename.to_string(),
                line: if self.show_linenumbers {
                    Some(frame.line as u32)
                } else {
                    None
                },
            },
        }
    }

    fn record_events(
        &mut self,
        now: u64,
        trace: &StackTrace,
        prev_trace: Option<StackTrace>,
    ) -> Result<(), Error> {
        // Load the previous frames for this thread.
        let prev_frames = prev_trace.map(|t| t.frames).unwrap_or_default();

        // Find the index where we first see new frames.
        let new_idx = prev_frames
            .iter()
            .rev()
            .zip(trace.frames.iter().rev())
            .position(|(a, b)| !self.should_merge_frames(a, b))
            .unwrap_or(min(prev_frames.len(), trace.frames.len()));

        // Publish end events for the previous frames that got dropped in the
        // most recent trace.
        for frame in prev_frames.iter().rev().skip(new_idx).rev() {
            self.writer.write(self.event(trace, frame, "E", now))?;
        }

        // Publish start events for frames that got added in the most recent
        // trace.
        for frame in trace.frames.iter().rev().skip(new_idx) {
            self.writer.write(self.event(trace, frame, "B", now))?;
        }

        Ok(())
    }

    pub fn increment(&mut self, traces: Vec<StackTrace>) -> Result<(), Error> {
        let now = self.start_ts.elapsed().as_micros() as u64;

        // Build up a new map of the current thread traces we see.
        let mut new_prev_traces: HashMap<_, StackTrace> = HashMap::new();

        // Process each new trace.
        for trace in traces.into_iter() {
            let prev_trace = self.prev_traces.remove(&trace.thread_id);
            self.record_events(now, &trace, prev_trace)?;
            new_prev_traces.insert(trace.thread_id, trace);
        }

        // If there are any remaining previous thread traces that we didn't
        // process above, just add end events.
        for trace in self
            .prev_traces
            .drain()
            .map(|(_, t)| t)
            .collect::<Vec<StackTrace>>()
        {
            for frame in &trace.frames {
                self.writer.write(self.event(&trace, frame, "E", now))?;
            }
        }

        // Save the current traces for next time.
        self.prev_traces = new_prev_traces;

        Ok(())
    }

    pub fn write(&mut self, w: &mut dyn Write) -> Result<(), Error> {
        // Add end events for any unfinished slices.
        let now = self.start_ts.elapsed().as_micros() as u64;
        for trace in self.prev_traces.values() {
            for frame in &trace.frames {
                self.writer.write(self.event(trace, frame, "E", now))?;
            }
        }

        let mut writer = Writer::new()?;
        std::mem::swap(&mut self.writer, &mut writer);
        let mut reader = writer.close()?;
        reader.rewind()?;
        std::io::copy(reader.as_file_mut(), w)?;

        self.start_ts = Instant::now();
        self.prev_traces.clear();

        Ok(())
    }
}
