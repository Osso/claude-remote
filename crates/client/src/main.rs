mod connection;

use anyhow::Result;
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
