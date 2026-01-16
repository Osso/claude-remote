mod connection;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use claude_remote_common::Config;
use claude_remote_protocol::{Request, Response};
use rustls::crypto::ring::default_provider;
use std::io::{self, BufRead, Write};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "claude-remote")]
#[command(about = "Remote client for Claude Code")]
struct Args {
    /// Send a single prompt and exit
    #[arg(short = 'p', long = "print")]
    prompt: Option<String>,

    /// Server address (host:port)
    #[arg(short, long)]
    server: Option<String>,

    /// Config directory
    #[arg(long)]
    config_dir: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a single prompt
    Prompt {
        /// The prompt text
        prompt: String,
    },
    /// Interactive mode
    Interactive,
    /// Configure client
    Config {
        /// Set default server
        #[arg(long)]
        server: Option<String>,
    },
    /// Ping the server
    Ping,
    /// Download a file from the server
    Get {
        /// Remote path on the server
        remote_path: String,
        /// Local path to save to (optional, defaults to filename)
        local_path: Option<String>,
    },
    /// Upload a file to the server
    Put {
        /// Local path to upload
        local_path: String,
        /// Remote path on the server
        remote_path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider
    default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    // Quiet logging by default, use RUST_LOG=info for verbose
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("warn".parse()?))
        .init();

    let config = match &args.config_dir {
        Some(dir) => Config::with_dir(dir.into()),
        None => Config::new(),
    };

    // Determine server address
    let server_addr = args
        .server
        .or_else(|| config.load_client().ok()?.default_server)
        .unwrap_or_else(|| "localhost:7433".to_string());

    // -p flag takes priority
    if let Some(prompt) = args.prompt {
        send_prompt(&config, &server_addr, &prompt).await?;
        return Ok(());
    }

    match args.command {
        Some(Commands::Prompt { prompt }) => {
            send_prompt(&config, &server_addr, &prompt).await?;
        }
        Some(Commands::Interactive) | None => {
            interactive_mode(&config, &server_addr).await?;
        }
        Some(Commands::Config { server }) => {
            configure(&config, server)?;
        }
        Some(Commands::Ping) => {
            ping(&config, &server_addr).await?;
        }
        Some(Commands::Get {
            remote_path,
            local_path,
        }) => {
            get_file(&config, &server_addr, &remote_path, local_path.as_deref()).await?;
        }
        Some(Commands::Put {
            local_path,
            remote_path,
        }) => {
            put_file(&config, &server_addr, &local_path, &remote_path).await?;
        }
    }

    Ok(())
}

async fn send_prompt(config: &Config, server_addr: &str, prompt: &str) -> Result<()> {
    let mut conn = connection::Connection::connect(config, server_addr).await?;

    conn.send(&Request::Prompt {
        content: prompt.to_string(),
        session_id: None,
    })
    .await?;

    // Receive and print responses
    loop {
        let response: Response = conn.receive().await?;

        match &response {
            Response::Claude { output } => {
                // Only print text from assistant messages, not from result
                if !output.is_result() {
                    if let Some(text) = output.text() {
                        print!("{}", text);
                        io::stdout().flush()?;
                    }
                }
                if output.is_result() {
                    println!();
                    break;
                }
            }
            Response::Error { message } => {
                eprintln!("Error: {}", message);
                break;
            }
            Response::Done { .. } => {
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

async fn interactive_mode(config: &Config, server_addr: &str) -> Result<()> {
    println!("Connecting to {}...", server_addr);
    let mut conn = connection::Connection::connect(config, server_addr).await?;
    println!("Connected. Type your prompts (Ctrl+D to exit).\n");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("> ");
        stdout.flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            // EOF
            break;
        }

        let prompt = line.trim();
        if prompt.is_empty() {
            continue;
        }

        conn.send(&Request::Prompt {
            content: prompt.to_string(),
            session_id: None,
        })
        .await?;

        // Receive and print responses
        loop {
            let response: Response = conn.receive().await?;

            match &response {
                Response::Claude { output } => {
                    // Only print text from assistant messages, not from result
                    if !output.is_result() {
                        if let Some(text) = output.text() {
                            print!("{}", text);
                            stdout.flush()?;
                        }
                    }
                    if output.is_result() {
                        println!("\n");
                        break;
                    }
                }
                Response::Error { message } => {
                    eprintln!("\nError: {}", message);
                    break;
                }
                Response::Done { .. } => {
                    println!();
                    break;
                }
                _ => {}
            }
        }
    }

    println!("\nGoodbye!");
    Ok(())
}

fn configure(config: &Config, server: Option<String>) -> Result<()> {
    let mut client_config = config.load_client().unwrap_or_default();

    if let Some(server) = server {
        client_config.default_server = Some(server.clone());
        println!("Default server set to: {}", server);
    }

    config.save_client(&client_config)?;
    println!("Configuration saved to {:?}", config.config_dir());

    Ok(())
}

async fn ping(config: &Config, server_addr: &str) -> Result<()> {
    let start = std::time::Instant::now();
    let mut conn = connection::Connection::connect(config, server_addr).await?;

    conn.send(&Request::Ping).await?;
    let response: Response = conn.receive().await?;

    let elapsed = start.elapsed();

    match response {
        Response::Pong => {
            println!("Pong from {} in {:?}", server_addr, elapsed);
        }
        Response::Error { message } => {
            eprintln!("Error: {}", message);
        }
        _ => {
            eprintln!("Unexpected response");
        }
    }

    Ok(())
}

async fn get_file(
    config: &Config,
    server_addr: &str,
    remote_path: &str,
    local_path: Option<&str>,
) -> Result<()> {
    use base64::Engine;
    use std::path::Path;

    let mut conn = connection::Connection::connect(config, server_addr).await?;

    conn.send(&Request::GetFile {
        path: remote_path.to_string(),
    })
    .await?;

    let response: Response = conn.receive().await?;

    match response {
        Response::FileContent { content } => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&content)
                .context("Failed to decode file content")?;

            let output_path = local_path.unwrap_or_else(|| {
                Path::new(remote_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("downloaded_file")
            });

            std::fs::write(output_path, &decoded)
                .context(format!("Failed to write to {}", output_path))?;

            println!("Downloaded {} -> {} ({} bytes)", remote_path, output_path, decoded.len());
        }
        Response::Error { message } => {
            eprintln!("Error: {}", message);
        }
        _ => {
            eprintln!("Unexpected response");
        }
    }

    Ok(())
}

async fn put_file(
    config: &Config,
    server_addr: &str,
    local_path: &str,
    remote_path: &str,
) -> Result<()> {
    use base64::Engine;

    let content = std::fs::read(local_path).context(format!("Failed to read {}", local_path))?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&content);

    let mut conn = connection::Connection::connect(config, server_addr).await?;

    conn.send(&Request::PutFile {
        path: remote_path.to_string(),
        content: encoded,
    })
    .await?;

    let response: Response = conn.receive().await?;

    match response {
        Response::FileOk => {
            println!("Uploaded {} -> {} ({} bytes)", local_path, remote_path, content.len());
        }
        Response::Error { message } => {
            eprintln!("Error: {}", message);
        }
        _ => {
            eprintln!("Unexpected response");
        }
    }

    Ok(())
}
