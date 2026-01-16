//! Approval dialog GUI using iced

use claude_remote_common::{Config, Fingerprint};
use iced::widget::{button, column, container, row, scrollable, text, Column};
use iced::{Element, Length, Task, Theme};
use std::collections::VecDeque;
use tokio::sync::{mpsc, oneshot};

/// Request for approval of a new client
pub struct ApprovalRequest {
    pub fingerprint: Fingerprint,
    pub response: oneshot::Sender<bool>,
}

/// Activity message for the log
#[derive(Debug, Clone)]
pub enum Activity {
    /// Client connected
    Connected { fingerprint: String },
    /// Client disconnected
    Disconnected { fingerprint: String },
    /// Prompt received from client
    Prompt { fingerprint: String, content: String },
    /// Response chunk from Claude
    Response { text: String },
    /// Request completed
    Completed,
    /// File downloaded
    FileGet { fingerprint: String, path: String },
    /// File uploaded
    FilePut { fingerprint: String, path: String },
}

/// Message type for the approval GUI
#[derive(Debug, Clone)]
pub enum Message {
    /// New approval request received (for future use)
    #[allow(dead_code)]
    NewRequest(Fingerprint),
    /// User approved the client
    Approve,
    /// User rejected the client
    Reject,
    /// Tick for checking new requests
    Tick,
}

/// Entry in the activity log
#[derive(Debug, Clone)]
struct LogEntry {
    prefix: String,
    content: String,
}

struct ApprovalApp {
    /// Pending approval requests
    pending: VecDeque<(Fingerprint, oneshot::Sender<bool>)>,
    /// Currently displayed request
    current: Option<Fingerprint>,
    /// Channel for receiving new requests
    request_rx: mpsc::Receiver<ApprovalRequest>,
    /// Channel for receiving activity
    activity_rx: mpsc::Receiver<Activity>,
    /// Activity log (recent entries)
    activity_log: VecDeque<LogEntry>,
    /// Config for saving approved clients
    config: Config,
}

const MAX_LOG_ENTRIES: usize = 100;

impl ApprovalApp {
    fn new(
        request_rx: mpsc::Receiver<ApprovalRequest>,
        activity_rx: mpsc::Receiver<Activity>,
        config: Config,
    ) -> (Self, Task<Message>) {
        (
            Self {
                pending: VecDeque::new(),
                current: None,
                request_rx,
                activity_rx,
                activity_log: VecDeque::new(),
                config,
            },
            Task::none(),
        )
    }

    fn add_log(&mut self, prefix: impl Into<String>, content: impl Into<String>) {
        self.activity_log.push_back(LogEntry {
            prefix: prefix.into(),
            content: content.into(),
        });
        while self.activity_log.len() > MAX_LOG_ENTRIES {
            self.activity_log.pop_front();
        }
    }

    #[allow(dead_code)]
    fn title(&self) -> String {
        if self.current.is_some() {
            "Claude Remote - New Connection".to_string()
        } else {
            "Claude Remote Server".to_string()
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::NewRequest(fingerprint) => {
                if self.current.is_none() {
                    self.current = Some(fingerprint);
                }
                Task::none()
            }

            Message::Approve => {
                if let Some((fingerprint, response)) = self.pending.pop_front() {
                    // Save to config
                    let name = format!("client-{}", &fingerprint.0[..8]);
                    if let Err(e) = self.config.add_trusted_client(&fingerprint, &name) {
                        tracing::error!("Failed to save trusted client: {}", e);
                    }

                    let _ = response.send(true);
                    self.current = self.pending.front().map(|(fp, _)| fp.clone());
                }
                Task::none()
            }

            Message::Reject => {
                if let Some((_, response)) = self.pending.pop_front() {
                    let _ = response.send(false);
                    self.current = self.pending.front().map(|(fp, _)| fp.clone());
                }
                Task::none()
            }

            Message::Tick => {
                // Check for new requests (non-blocking)
                while let Ok(request) = self.request_rx.try_recv() {
                    let fingerprint = request.fingerprint.clone();
                    self.pending.push_back((request.fingerprint, request.response));
                    if self.current.is_none() {
                        self.current = Some(fingerprint);
                    }
                }

                // Check for activity messages
                while let Ok(activity) = self.activity_rx.try_recv() {
                    match activity {
                        Activity::Connected { fingerprint } => {
                            self.add_log("CONNECT", format!("{}", &fingerprint[..16]));
                        }
                        Activity::Disconnected { fingerprint } => {
                            self.add_log("DISCONNECT", format!("{}", &fingerprint[..16]));
                        }
                        Activity::Prompt { fingerprint, content } => {
                            let preview: String = content.chars().take(60).collect();
                            let ellipsis = if content.len() > 60 { "..." } else { "" };
                            self.add_log(
                                format!("[{}]", &fingerprint[..8]),
                                format!("{}{}", preview, ellipsis),
                            );
                        }
                        Activity::Response { text } => {
                            let preview: String = text.chars().take(60).collect();
                            let ellipsis = if text.len() > 60 { "..." } else { "" };
                            self.add_log("CLAUDE", format!("{}{}", preview, ellipsis));
                        }
                        Activity::Completed => {
                            self.add_log("---", "completed");
                        }
                        Activity::FileGet { fingerprint, path } => {
                            self.add_log(format!("[{}]", &fingerprint[..8]), format!("GET {}", path));
                        }
                        Activity::FilePut { fingerprint, path } => {
                            self.add_log(format!("[{}]", &fingerprint[..8]), format!("PUT {}", path));
                        }
                    }
                }

                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        // Header with approval dialog or status
        let header = if let Some(fingerprint) = &self.current {
            column![
                text("New Connection Request").size(36),
                text(format!("Fingerprint: {}...", &fingerprint.0[..16])).size(24),
                row![
                    button(text("Approve").size(24))
                        .padding(16)
                        .on_press(Message::Approve),
                    text("  "),
                    button(text("Reject").size(24))
                        .padding(16)
                        .on_press(Message::Reject),
                ]
            ]
            .spacing(12)
        } else {
            column![
                text("Claude Remote Server").size(36),
                text(format!(
                    "Waiting... ({} pending)",
                    self.pending.len()
                ))
                .size(24),
            ]
            .spacing(10)
        };

        // Activity log
        let grey = iced::Color::from_rgb(0.5, 0.5, 0.5);
        let log_entries: Vec<Element<'_, Message>> = self
            .activity_log
            .iter()
            .map(|entry| {
                let is_grey = entry.prefix == "CONNECT" || entry.prefix == "DISCONNECT";
                if is_grey {
                    row![
                        text(&entry.prefix).size(20).width(Length::Fixed(140.0)).color(grey),
                        text(&entry.content).size(20).color(grey),
                    ]
                } else {
                    row![
                        text(&entry.prefix).size(20).width(Length::Fixed(140.0)),
                        text(&entry.content).size(20),
                    ]
                }
                .spacing(12)
                .into()
            })
            .collect();

        let log_content = if log_entries.is_empty() {
            Column::new().push(text("No activity yet").size(22))
        } else {
            Column::with_children(log_entries).spacing(6)
        };

        let activity_log = scrollable(log_content)
            .width(Length::Fill)
            .height(Length::Fill);

        let content = column![
            header,
            text("─".repeat(30)).size(20),
            text("Activity Log").size(26),
            activity_log,
        ]
        .spacing(16);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(24)
            .into()
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        iced::time::every(std::time::Duration::from_millis(100)).map(|_| Message::Tick)
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

/// Run the approval GUI
pub fn run_gui(
    request_rx: mpsc::Receiver<ApprovalRequest>,
    activity_rx: mpsc::Receiver<Activity>,
    config: Config,
) -> anyhow::Result<()> {
    iced::application("Claude Remote Server", ApprovalApp::update, ApprovalApp::view)
        .subscription(ApprovalApp::subscription)
        .theme(ApprovalApp::theme)
        .window_size((800.0, 600.0))
        .run_with(move || ApprovalApp::new(request_rx, activity_rx, config))?;

    Ok(())
}
