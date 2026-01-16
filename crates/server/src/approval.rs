//! Approval dialog GUI using iced

use claude_remote_common::{Config, Fingerprint};
use iced::widget::{button, column, container, row, text};
use iced::{Element, Length, Task, Theme};
use std::collections::VecDeque;
use tokio::sync::{mpsc, oneshot};

/// Request for approval of a new client
pub struct ApprovalRequest {
    pub fingerprint: Fingerprint,
    pub response: oneshot::Sender<bool>,
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

struct ApprovalApp {
    /// Pending approval requests
    pending: VecDeque<(Fingerprint, oneshot::Sender<bool>)>,
    /// Currently displayed request
    current: Option<Fingerprint>,
    /// Channel for receiving new requests
    request_rx: mpsc::Receiver<ApprovalRequest>,
    /// Config for saving approved clients
    config: Config,
}

impl ApprovalApp {
    fn new(request_rx: mpsc::Receiver<ApprovalRequest>, config: Config) -> (Self, Task<Message>) {
        (
            Self {
                pending: VecDeque::new(),
                current: None,
                request_rx,
                config,
            },
            Task::none(),
        )
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
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let content = if let Some(fingerprint) = &self.current {
            column![
                text("New Connection Request").size(24),
                text("").size(16),
                text("A new client is requesting access:").size(16),
                text("").size(8),
                text(format!("Fingerprint:")).size(14),
                text(fingerprint.to_string()).size(12),
                text("").size(16),
                row![
                    button(text("Approve").size(16))
                        .padding(10)
                        .on_press(Message::Approve),
                    text("  "),
                    button(text("Reject").size(16))
                        .padding(10)
                        .on_press(Message::Reject),
                ]
            ]
            .spacing(8)
        } else {
            column![
                text("Claude Remote Server").size(24),
                text("").size(16),
                text("Waiting for connections...").size(16),
                text("").size(8),
                text(format!("Pending requests: {}", self.pending.len())).size(14),
            ]
            .spacing(8)
        };

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(20)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
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
pub fn run_gui(request_rx: mpsc::Receiver<ApprovalRequest>, config: Config) -> anyhow::Result<()> {
    iced::application("Claude Remote Server", ApprovalApp::update, ApprovalApp::view)
        .subscription(ApprovalApp::subscription)
        .theme(ApprovalApp::theme)
        .window_size((400.0, 300.0))
        .run_with(move || ApprovalApp::new(request_rx, config))?;

    Ok(())
}
