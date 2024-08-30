use std::cmp::min;
use std::collections::HashMap;
use std::io::BufWriter;
use std::io::Seek;
use std::io::Write;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::Error;
use flate2::write::GzEncoder;
use serde_derive::Serialize;
use tempfile::NamedTempFile;
use zstd::stream::read::Decoder;
use zstd::stream::write::Encoder;

use crate::stack_trace::Frame;
use crate::stack_trace::StackTrace;

#[derive(Clone, Debug, Serialize)]
struct Args<'a> {
    pub filename: &'a str,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
struct Event<'a> {
    pub args: Args<'a>,
    pub cat: &'a str,
    pub name: &'a str,
    pub ph: &'a str,
    pub pid: u64,
    pub tid: u64,
    pub ts: u64,
}

struct Writer {
    file: BufWriter<Encoder<'static, BufWriter<NamedTempFile>>>,
    first: bool,
}

impl Writer {
    fn new() -> std::io::Result<Self> {
        let mut file = BufWriter::new(Encoder::new(BufWriter::new(NamedTempFile::new()?), 0)?);
        write!(file, "[")?;
        Ok(Writer { file, first: true })
    }

    fn write(&mut self, event: Event) -> Result<(), Error> {
        if self.first {
            self.first = false;
        } else {
            write!(self.file, ",")?;
        }
        serde_json::to_writer(&mut self.file, &event)?;
        Ok(())
    }

    fn close(mut self) -> Result<NamedTempFile, Error> {
        writeln!(self.file, "]")?;
        Ok(self
            .file
            .into_inner()
            .map_err(|_| anyhow!("fail"))?
            .finish()?
            .into_inner()?)
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
        (!self.show_linenumbers || a.line == b.line) && a.name == b.name && a.filename == b.filename
    }

    fn event<'a>(
        &self,
        trace: &'a StackTrace,
        frame: &'a Frame,
        phase: &'a str,
        ts: u64,
    ) -> Event<'a> {
        Event {
            tid: trace.thread_id,
            pid: trace.pid as u64,
            name: frame.name.as_str(),
            cat: "py-spy",
            ph: phase,
            ts,
            args: Args {
                filename: frame.filename.as_str(),
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
        let mut new_prev_traces: HashMap<_, StackTrace> = HashMap::with_capacity(traces.len());

        // Process each new trace.
        for trace in traces.into_iter() {
            let prev_trace = self.prev_traces.remove(&trace.thread_id);
            self.record_events(now, &trace, prev_trace)?;
            new_prev_traces.insert(trace.thread_id, trace);
        }

        // If there are any remaining previous thread traces that we didn't
        // process above, just add end events.
        for trace in self.prev_traces.values() {
            for frame in &trace.frames {
                self.writer.write(self.event(trace, frame, "E", now))?;
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

        // Re-encode the buffered events from zstd to gzip as tools like
        // chrome://tracing and perfetto nativelt support the latter (but
        // not the former).
        let mut writer = Writer::new()?;
        std::mem::swap(&mut self.writer, &mut writer);
        let mut reader = writer.close()?;
        reader.rewind()?;
        let mut reader = Decoder::new(reader)?;
        let mut writer = GzEncoder::new(w, flate2::Compression::default());
        std::io::copy(&mut reader, &mut writer)?;

        self.start_ts = Instant::now();
        self.prev_traces.clear();

        Ok(())
    }
}
