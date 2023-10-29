use std::collections::VecDeque;

use tokio::sync::broadcast;

pub struct LogChan<T> {
    log: VecDeque<T>,
    tx: broadcast::Sender<T>,
}

impl<T: Clone> LogChan<T> {
    pub fn now_and_future(&self) -> (VecDeque<T>, broadcast::Receiver<T>) {
        (self.log.clone(), self.tx.subscribe())
    }

    pub fn push(&mut self, data: T) {
        self.log.push_back(data.clone());
        self.log.truncate(256);
        let _ = self.tx.send(data);
    }
}

impl<T: Clone> Default for LogChan<T> {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(128);
        Self {
            log: VecDeque::new(),
            tx,
        }
    }
}
