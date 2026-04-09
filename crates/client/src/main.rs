use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use claude_remote_client::Connection;
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
    /// Shutdown the server
    Shutdown,
    /// Update server (pull, build, restart)
    Update {
        /// Project directory on the server
        #[arg(long, default_value = "C:\\Users\\adeia\\Projects\\claude-remote")]
        project_dir: String,
    },
    /// Execute a shell command on the server
    Exec {
        /// Command to execute
        command: String,
        /// Working directory
        #[arg(long)]
        cwd: Option<String>,
    },
    /// Show server status (uptime, version)
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider();
    let args = Args::parse();
    init_logging()?;
    let config = load_config(args.config_dir.as_deref());
    let server_addr = resolve_server_addr(args.server.clone(), &config);
    run_command(args, &config, &server_addr).await
}

fn install_crypto_provider() {
    default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
}

fn init_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("warn".parse()?))
        .init();
    Ok(())
}

fn load_config(config_dir: Option<&str>) -> Config {
    match config_dir {
        Some(dir) => Config::with_dir(dir.into()),
        None => Config::new(),
    }
}

fn resolve_server_addr(server: Option<String>, config: &Config) -> String {
    server
        .or_else(|| config.load_client().ok()?.default_server)
        .unwrap_or_else(|| "localhost:7433".to_string())
}

async fn run_command(args: Args, config: &Config, server_addr: &str) -> Result<()> {
    if let Some(prompt) = args.prompt {
        return send_prompt(config, server_addr, &prompt).await;
    }

    match args.command {
        Some(Commands::Prompt { prompt }) => send_prompt(config, server_addr, &prompt).await,
        Some(Commands::Interactive) | None => interactive_mode(config, server_addr).await,
        Some(Commands::Config { server }) => configure(config, server),
        Some(Commands::Ping) => ping(config, server_addr).await,
        Some(Commands::Get {
            remote_path,
            local_path,
        }) => get_file(config, server_addr, &remote_path, local_path.as_deref()).await,
        Some(Commands::Put {
            local_path,
            remote_path,
        }) => put_file(config, server_addr, &local_path, &remote_path).await,
        Some(Commands::Shutdown) => shutdown(config, server_addr).await,
        Some(Commands::Update { project_dir }) => update(config, server_addr, &project_dir).await,
        Some(Commands::Exec { command, cwd }) => {
            exec(config, server_addr, &command, cwd.as_deref()).await
        }
        Some(Commands::Status) => status(config, server_addr).await,
    }
}

async fn send_prompt(config: &Config, server_addr: &str, prompt: &str) -> Result<()> {
    let mut conn = Connection::connect(config, server_addr).await?;
    send_prompt_request(&mut conn, prompt).await?;
    stream_prompt_responses(&mut conn, false).await
}

async fn send_prompt_request(conn: &mut Connection, prompt: &str) -> Result<()> {
    conn.send(&Request::Prompt {
        content: prompt.to_string(),
        session_id: None,
    })
    .await
}

async fn stream_prompt_responses(conn: &mut Connection, interactive: bool) -> Result<()> {
    loop {
        let response: Response = conn.receive().await?;
        if handle_prompt_response(&response, interactive)? {
            break;
        }
    }
    Ok(())
}

fn handle_prompt_response(response: &Response, interactive: bool) -> Result<bool> {
    match response {
        Response::Claude { output } => handle_claude_prompt_output(output, interactive),
        Response::Error { message } => {
            print_prompt_error(message, interactive);
            Ok(true)
        }
        Response::Done { .. } => {
            if interactive {
                println!();
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn handle_claude_prompt_output(
    output: &claude_remote_protocol::claude::ClaudeOutput,
    interactive: bool,
) -> Result<bool> {
    if output.is_result() {
        print_result_separator(interactive);
        return Ok(true);
    }
    if let Some(text) = output.text() {
        print!("{}", text);
        io::stdout().flush()?;
    }
    Ok(false)
}

fn print_result_separator(interactive: bool) {
    if interactive {
        println!("\n");
    } else {
        println!();
    }
}

fn print_prompt_error(message: &str, interactive: bool) {
    if interactive {
        eprintln!("\nError: {}", message);
    } else {
        eprintln!("Error: {}", message);
    }
}

async fn interactive_mode(config: &Config, server_addr: &str) -> Result<()> {
    println!("Connecting to {}...", server_addr);
    let mut conn = Connection::connect(config, server_addr).await?;
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

        send_prompt_request(&mut conn, prompt).await?;
        stream_prompt_responses(&mut conn, true).await?;
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
    let mut conn = Connection::connect(config, server_addr).await?;

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

// 8MB chunks (leaves room for base64 overhead within 16MB message limit)
const CHUNK_SIZE: u64 = 8 * 1024 * 1024;

async fn get_file(
    config: &Config,
    server_addr: &str,
    remote_path: &str,
    local_path: Option<&str>,
) -> Result<()> {
    use std::path::Path;

    let mut conn = Connection::connect(config, server_addr).await?;
    let file_size = stat_remote_file(&mut conn, remote_path).await?;

    let output_path = local_path.unwrap_or_else(|| {
        Path::new(remote_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("downloaded_file")
    });

    if file_size <= CHUNK_SIZE {
        let decoded = fetch_small_file(&mut conn, remote_path).await?;
        std::fs::write(output_path, &decoded)
            .context(format!("Failed to write to {}", output_path))?;
        println!(
            "Downloaded {} -> {} ({} bytes)",
            remote_path,
            output_path,
            decoded.len()
        );
        return Ok(());
    }

    fetch_large_file(&mut conn, remote_path, output_path, file_size).await?;
    Ok(())
}

async fn stat_remote_file(conn: &mut Connection, remote_path: &str) -> Result<u64> {
    conn.send(&Request::StatFile {
        path: remote_path.to_string(),
    })
    .await?;
    match conn.receive().await? {
        Response::FileStat { size } => Ok(size),
        Response::Error { message } => anyhow::bail!("Failed to stat file: {}", message),
        _ => anyhow::bail!("Unexpected response to stat"),
    }
}

async fn fetch_small_file(conn: &mut Connection, remote_path: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    conn.send(&Request::GetFile {
        path: remote_path.to_string(),
    })
    .await?;

    match conn.receive().await? {
        Response::FileContent { content } => base64::engine::general_purpose::STANDARD
            .decode(&content)
            .context("Failed to decode file content"),
        Response::Error { message } => anyhow::bail!("Error: {}", message),
        _ => anyhow::bail!("Unexpected response"),
    }
}

async fn fetch_large_file(
    conn: &mut Connection,
    remote_path: &str,
    output_path: &str,
    file_size: u64,
) -> Result<()> {
    use std::io::Write;

    let mut file =
        std::fs::File::create(output_path).context(format!("Failed to create {}", output_path))?;
    let num_chunks = file_size.div_ceil(CHUNK_SIZE);
    let mut offset = 0u64;
    let mut chunk_num = 0u64;

    while offset < file_size {
        chunk_num += 1;
        let length = std::cmp::min(CHUNK_SIZE, file_size - offset);
        print_transfer_progress("Downloading", chunk_num, num_chunks, offset, file_size);

        conn.send(&Request::GetFileChunk {
            path: remote_path.to_string(),
            offset,
            length,
        })
        .await?;

        let decoded = decode_chunk_response(conn.receive().await?, "downloading")?;
        file.write_all(&decoded).context("Failed to write chunk")?;
        offset += decoded.len() as u64;
    }

    eprintln!();
    println!(
        "Downloaded {} -> {} ({} bytes)",
        remote_path, output_path, file_size
    );
    Ok(())
}

fn decode_chunk_response(response: Response, operation: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    match response {
        Response::FileChunk { content } => base64::engine::general_purpose::STANDARD
            .decode(&content)
            .context("Failed to decode chunk"),
        Response::Error { message } => {
            eprintln!();
            anyhow::bail!("Error {} chunk: {}", operation, message);
        }
        _ => {
            eprintln!();
            anyhow::bail!("Unexpected response");
        }
    }
}

fn print_transfer_progress(action: &str, chunk_num: u64, num_chunks: u64, offset: u64, total: u64) {
    eprint!(
        "\r{} chunk {}/{} ({:.1}%)...",
        action,
        chunk_num,
        num_chunks,
        (offset as f64 / total as f64) * 100.0
    );
}

async fn put_file(
    config: &Config,
    server_addr: &str,
    local_path: &str,
    remote_path: &str,
) -> Result<()> {
    let metadata =
        std::fs::metadata(local_path).context(format!("Failed to stat {}", local_path))?;
    let file_size = metadata.len();

    println!("Uploading {} ({} bytes)...", local_path, file_size);

    let mut conn = Connection::connect(config, server_addr).await?;

    if file_size <= CHUNK_SIZE {
        upload_small_file(&mut conn, local_path, remote_path).await?;
        return Ok(());
    }

    let mut file =
        std::fs::File::open(local_path).context(format!("Failed to open {}", local_path))?;
    upload_large_file(&mut conn, &mut file, remote_path, file_size).await?;
    println!(
        "Uploaded {} -> {} ({} bytes)",
        local_path, remote_path, file_size
    );
    Ok(())
}

async fn upload_small_file(
    conn: &mut Connection,
    local_path: &str,
    remote_path: &str,
) -> Result<()> {
    use base64::Engine;
    let content = std::fs::read(local_path).context(format!("Failed to read {}", local_path))?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&content);

    conn.send(&Request::PutFile {
        path: remote_path.to_string(),
        content: encoded,
    })
    .await?;

    ensure_file_ok(conn.receive().await?, "upload")?;
    println!(
        "Uploaded {} -> {} ({} bytes)",
        local_path,
        remote_path,
        content.len()
    );
    Ok(())
}

async fn upload_large_file(
    conn: &mut Connection,
    file: &mut std::fs::File,
    remote_path: &str,
    file_size: u64,
) -> Result<()> {
    use base64::Engine;
    use std::io::Read;

    let num_chunks = file_size.div_ceil(CHUNK_SIZE);
    let mut offset = 0u64;
    let mut chunk_num = 0u64;

    while offset < file_size {
        chunk_num += 1;
        let length = std::cmp::min(CHUNK_SIZE, file_size - offset) as usize;
        print_transfer_progress("Uploading", chunk_num, num_chunks, offset, file_size);

        let mut buffer = vec![0u8; length];
        file.read_exact(&mut buffer)
            .context("Failed to read chunk")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);

        conn.send(&Request::PutFileChunk {
            path: remote_path.to_string(),
            offset,
            total_size: file_size,
            content: encoded,
        })
        .await?;

        ensure_file_ok(conn.receive().await?, "uploading")?;
        offset += length as u64;
    }

    eprintln!();
    Ok(())
}

fn ensure_file_ok(response: Response, operation: &str) -> Result<()> {
    match response {
        Response::FileOk => Ok(()),
        Response::Error { message } => {
            eprintln!();
            anyhow::bail!("Error {} chunk: {}", operation, message);
        }
        _ => {
            eprintln!();
            anyhow::bail!("Unexpected response");
        }
    }
}

async fn shutdown(config: &Config, server_addr: &str) -> Result<()> {
    let mut conn = Connection::connect(config, server_addr).await?;

    println!("Requesting server shutdown...");
    conn.send(&Request::Shutdown).await?;

    let response: Response = conn.receive().await?;

    match response {
        Response::ShuttingDown => {
            println!("Server is shutting down");
        }
        Response::Error { message } => {
            anyhow::bail!("Error: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response");
        }
    }

    Ok(())
}

async fn update(config: &Config, server_addr: &str, project_dir: &str) -> Result<()> {
    let mut conn = Connection::connect(config, server_addr).await?;

    println!("Starting server update from {}...", project_dir);
    conn.send(&Request::Update {
        project_dir: project_dir.to_string(),
    })
    .await?;

    // Receive progress updates until complete or error
    loop {
        let response: Response = conn.receive().await?;

        match response {
            Response::UpdateProgress { message } => {
                println!("  {}", message);
            }
            Response::UpdateComplete { new_binary } => {
                println!("Update complete! New binary: {}", new_binary);
                println!("Server will restart momentarily...");
                break;
            }
            Response::Error { message } => {
                anyhow::bail!("Update failed: {}", message);
            }
            _ => {
                anyhow::bail!("Unexpected response");
            }
        }
    }

    // Wait a moment then verify new server is up
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    match Connection::connect(config, server_addr).await {
        Ok(mut conn) => {
            conn.send(&Request::Ping).await?;
            let response: Response = conn.receive().await?;
            if matches!(response, Response::Pong) {
                println!("New server is running!");
            }
        }
        Err(e) => {
            println!("Warning: Could not verify new server: {}", e);
        }
    }

    Ok(())
}

async fn exec(config: &Config, server_addr: &str, command: &str, cwd: Option<&str>) -> Result<()> {
    let mut conn = Connection::connect(config, server_addr).await?;

    conn.send(&Request::Exec {
        command: command.to_string(),
        cwd: cwd.map(String::from),
    })
    .await?;

    let response: Response = conn.receive().await?;

    match response {
        Response::ExecResult {
            exit_code,
            stdout,
            stderr,
        } => {
            if !stdout.is_empty() {
                print!("{}", stdout);
            }
            if !stderr.is_empty() {
                eprint!("{}", stderr);
            }
            if let Some(code) = exit_code {
                if code != 0 {
                    std::process::exit(code);
                }
            }
        }
        Response::Error { message } => {
            anyhow::bail!("Error: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response");
        }
    }

    Ok(())
}

async fn status(config: &Config, server_addr: &str) -> Result<()> {
    let mut conn = Connection::connect(config, server_addr).await?;

    conn.send(&Request::Status).await?;

    let response: Response = conn.receive().await?;

    match response {
        Response::StatusInfo {
            uptime_secs,
            version,
            started_at,
        } => {
            let hours = uptime_secs / 3600;
            let mins = (uptime_secs % 3600) / 60;
            let secs = uptime_secs % 60;

            println!("Server Status:");
            println!("  Version:    {}", version);
            println!("  Started at: {} (Unix timestamp)", started_at);
            println!("  Uptime:     {}h {}m {}s", hours, mins, secs);
        }
        Response::Error { message } => {
            anyhow::bail!("Error: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response");
        }
    }

    Ok(())
}
