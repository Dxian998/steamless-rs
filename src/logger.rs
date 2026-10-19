#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Success,
    Error,
}

pub trait Logger {
    fn log(&self, level: Level, message: &str);
}

pub struct NullLogger;

impl Logger for NullLogger {
    fn log(&self, _level: Level, _message: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sink(std::sync::Mutex<Vec<String>>);

    impl Logger for Sink {
        fn log(&self, level: Level, message: &str) {
            self.0.lock().unwrap().push(format!("{level:?}: {message}"));
        }
    }

    #[test]
    fn logger_receives_messages() {
        let sink = Sink(std::sync::Mutex::new(Vec::new()));
        sink.log(Level::Info, "hello");
        let messages = sink.0.lock().unwrap();
        assert_eq!(messages[0], "Info: hello");
    }
}
