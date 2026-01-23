# Indago Burp Suite Extension

A Burp Suite Professional extension that provides seamless integration with [Indago](https://github.com/Su1ph3r/indago), the AI-powered API security fuzzer.

## Features

- **Context Menu Integration** - Right-click on any request to send it to Indago
- **Export Queue** - Batch requests for scanning with Indago
- **Direct Scan Launch** - Execute Indago scans directly from Burp with live output streaming
- **Finding Import** - Import Indago results back into Burp as audit issues
- **Custom Tab UI** - Manage exports, view findings, configure settings
- **Severity Color Coding** - Findings displayed with color-coded severity levels

## Requirements

- Burp Suite Professional 2023.1 or later
- Java 17 or later (required by Montoya API)
- [Indago](https://github.com/Su1ph3r/indago) installed on your system
- Gradle 8.x (for building from source)

## Building

```bash
cd extensions/burp

# Build the extension JAR
./gradlew build

# Output: build/libs/indago-burp-extension-1.0.0.jar
```

### Build Requirements

- **Java 17+**: Set `JAVA_HOME` if needed
  ```bash
  # macOS with Homebrew
  brew install openjdk@17
  export JAVA_HOME=/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
  ```

## Installation

1. Build the extension (see above) or download a release JAR
2. Open Burp Suite Professional
3. Go to **Extensions** > **Installed**
4. Click **Add**
5. Select **Extension type**: Java
6. Click **Select file** and choose the JAR file
7. Click **Next** to load the extension

The extension will create a new **Indago** tab in the Burp Suite interface.

## Configuration

After loading the extension, go to the **Indago** tab > **Settings** and configure:

### Required Settings

| Setting | Description |
|---------|-------------|
| **Indago Path** | Full path to the Indago binary (e.g., `/usr/local/bin/indago` or `C:\indago\indago.exe`) |

Click **Validate** to verify the Indago installation is working.

### LLM Provider Settings (Optional)

Configure an LLM provider for AI-powered analysis:

| Setting | Description | Example |
|---------|-------------|---------|
| Provider | LLM provider | `openai`, `anthropic`, `ollama`, `lmstudio` |
| Model | Model name | `gpt-4o`, `claude-sonnet-4-20250514`, `llama3.3` |
| API Key | API key for cloud providers | `sk-...` |
| LLM URL | Base URL for local providers | `http://localhost:11434/v1` |
| Use LLM Payloads | Enable AI-generated context-aware payloads | Checkbox |
| LLM Concurrency | Number of concurrent LLM requests | `8` |

### Scan Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Concurrency | 10 | Number of concurrent HTTP requests |
| Rate Limit | 10.0 | Requests per second |
| Timeout | 30 | Request timeout in seconds |
| Verify SSL | true | Verify SSL certificates |

### Proxy Settings

Route Indago traffic through Burp for visibility in Proxy history:

| Setting | Default | Description |
|---------|---------|-------------|
| Use Proxy | false | Route Indago traffic through proxy |
| Host | 127.0.0.1 | Proxy host |
| Port | 8080 | Proxy port (should match Burp's proxy listener) |

### Output Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Auto Import | true | Automatically import findings to Burp's issue list |

## Usage

### Adding Requests to Indago

1. Select requests in Burp (Proxy history, Repeater, Site map, etc.)
2. Right-click and select **Indago** > **Send to Indago**
3. Requests are added to the export queue

### Scanning with Indago

**Option 1: From Export Queue**
1. Go to **Indago** tab > **Export Queue**
2. Review queued requests
3. Click **Scan with Indago**

**Option 2: Immediate Scan**
1. Right-click on requests in Burp
2. Select **Indago** > **Scan with Indago Now**
3. Scan starts immediately

**Option 3: From Scan Tab**
1. Add requests to the export queue
2. Go to **Indago** tab > **Scan**
3. Click **Start Scan**
4. Monitor progress in real-time

### Exporting to Burp XML

To export requests for use with the Indago CLI directly:

1. Right-click on requests
2. Select **Indago** > **Export as Burp XML...**
3. Choose a save location

Then run Indago manually:
```bash
indago scan --burp exported-requests.xml --provider anthropic
```

### Viewing Results

Findings are displayed in the **Indago** > **Findings** tab:

- **Table view** with severity color coding
- **Details panel** with full finding information
- **Request/Response** tabs with evidence
- **Add to Burp Issues** button to add selected findings
- **Import JSON Results** to load results from previous scans

### Workflow Example

```
1. Browse target through Burp Proxy
2. Select interesting API requests from Proxy History
3. Right-click > Indago > Send to Indago
4. Go to Indago tab > Scan > Start Scan
5. Monitor scan progress in real-time
6. Review findings in the Findings tab
7. Findings are automatically added to Burp's issue list
```

## Architecture

```
extensions/burp/
├── build.gradle.kts                 # Gradle build configuration
├── src/main/java/com/indago/burp/
│   ├── IndagoExtension.java         # Main entry point (BurpExtension)
│   ├── config/
│   │   ├── IndagoConfig.java        # Configuration model
│   │   └── ConfigStore.java         # Persistence via Burp preferences
│   ├── model/
│   │   ├── ExportItem.java          # Export queue item wrapper
│   │   └── IndagoFinding.java       # Finding data model (matches Indago JSON)
│   ├── export/
│   │   └── BurpXmlExporter.java     # Export to Burp XML format
│   ├── import_/
│   │   ├── JsonImporter.java        # Parse Indago JSON results
│   │   └── IndagoAuditIssue.java    # AuditIssue adapter for Burp
│   ├── scanner/
│   │   ├── IndagoScanLauncher.java  # Execute Indago CLI
│   │   └── ProcessManager.java      # Process lifecycle management
│   ├── menu/
│   │   └── IndagoContextMenuProvider.java  # Right-click context menu
│   └── ui/
│       ├── IndagoTab.java           # Main tab container
│       ├── ConfigPanel.java         # Settings UI
│       ├── ExportPanel.java         # Export queue management
│       ├── ScanPanel.java           # Scan controls and output
│       └── FindingsPanel.java       # Findings table and details
└── README.md
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         Burp Suite                              │
├─────────────────────────────────────────────────────────────────┤
│  HTTP Request ──► BurpXmlExporter ──► temp.xml                  │
│                                           │                     │
│                                           ▼                     │
│                                    ┌─────────────┐              │
│                                    │   Indago    │              │
│                                    │    CLI      │              │
│                                    └─────────────┘              │
│                                           │                     │
│                                           ▼                     │
│  Burp Issues ◄── IndagoAuditIssue ◄── JsonImporter ◄── .json   │
└─────────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Extension fails to load

- Ensure **Java 17+** is installed and accessible
- Check **Burp Extensions > Errors** tab for detailed error messages
- Verify the JAR was built successfully with all dependencies

### Scan doesn't start

- Verify Indago path is correct in Settings
- Click **Validate** to test the Indago installation
- Check Burp Extensions output for error messages
- Ensure export queue is not empty

### No findings imported

- Ensure **Auto Import** is enabled in Settings
- Manually import using **Import JSON Results** in Findings tab
- Verify Indago completed successfully (check scan output)

### Requests not appearing in export queue

- Ensure the request has been sent (has a response)
- Try re-selecting the request and using the context menu

### LLM provider not working

- Verify API key is correct
- For local providers (ollama, lmstudio), ensure the server is running
- Check the LLM URL is correct (e.g., `http://localhost:11434/v1` for ollama)

## Security Considerations

- **API Keys**: Stored in Burp's preferences (plaintext). Keep your Burp project files secure.
- **Temporary Files**: Scan input/output files are created in the system temp directory with `deleteOnExit()`.
- **Process Visibility**: When running scans, command-line arguments may be visible in process listings.

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Montoya API | 2025.12 | Burp Suite extension API |
| Gson | 2.10.1 | JSON parsing |

## Contributing

Contributions are welcome! Please submit issues and pull requests to the [Indago repository](https://github.com/Su1ph3r/indago).

### Development Setup

1. Clone the repository
2. Open `extensions/burp/` in your IDE
3. Import as Gradle project
4. Build: `./gradlew build`
5. Load JAR in Burp to test

## License

This extension is part of the Indago project and is released under the same license.
