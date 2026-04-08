# MISP MCP Server

A Model Context Protocol (MCP) server that integrates with the MISP (Malware Information Sharing Platform) to provide threat intelligence capabilities to Large Language Models.

## Features

- **Threat Intelligence Queries**: Retrieve malicious IPs, domains, and hashes from MISP
- **Advanced Search**: Search for attributes, events, and threat details
- **Event Management**: Create, publish, and manage MISP events
- **IoC Management**: Add attributes, sightings, and tags to events
- **Galaxy Integration**: Access galaxy clusters and event galaxies
- **Feed Management**: List and manage MISP feeds

## Prerequisites

- Python 3.8 or higher
- [MISP](https://github.com/MISP/MISP) instance with API access
- API key with appropriate permissions

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/misp-mcp-server.git
   cd misp-mcp-server
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

## Configuration

Set the following environment variables to connect to your MISP instance:

- `MISP_URL` - URL of your MISP instance (default: "https://misp.local")
- `MISP_API_KEY` - Your MISP API key (required)

## Usage

### Running as a standalone server

```bash
python misp_mcp_server.py
```

### Testing with MCP Inspector

```bash
mcp dev misp_mcp_server.py
```

### Installing in Claude Desktop

Edit your Claude Desktop configuration file:

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

Add the MISP MCP server configuration:

```json
{
  "mcpServers": {
    "misp-intelligence": {
      "command": "python",
      "args": ["/path/to/misp_mcp_server.py"],
      "env": {
        "MISP_URL": "https://your-misp-instance.com",
        "MISP_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Available Tools

### Threat Intelligence Retrieval

- `get_malicious_ips`: Get all malicious IP addresses marked for IDS
- `get_malicious_domains`: Get all malicious domains marked for IDS
- `get_malicious_hashes`: Get malicious file hashes (md5, sha1, sha256) marked for IDS

### Search Tools

- `search_ip_in_misp`: Check if an IP is present in MISP and marked for IDS
- `search_attribute`: Search for any attribute by value (IP, domain, hash, url, etc.)
- `get_threat_details`: Get full threat context for an indicator from MISP events

### Event Management

- `list_misp_events`: List MISP events with metadata
- `get_event`: Get full event details by ID
- `get_event_indicators`: Get all IOCs for an event grouped by type
- `search_events`: Search events with filters (tags, type, value, date range, etc.)
- `search_attributes`: Search attributes with filters (type, category, tags, etc.)

### Event Creation and Modification

- `add_event`: Create a new MISP event
- `add_attribute`: Add an attribute to an existing event
- `publish_event`: Publish an event to make it visible to the community
- `add_sighting`: Add a sighting to an attribute (positive/negative/expiration)
- `add_tag_to_event`: Add a tag to an event
- `delete_event`: Delete an event by ID

### Metadata and Feeds

- `list_tags`: List available tags in MISP
- `list_feeds`: List configured MISP feeds
- `list_galaxy_clusters`: List galaxy clusters (MITRE, malware, etc.)
- `get_event_galaxies`: Get galaxy clusters attached to an event

## API Reference

All tools return JSON responses. The server communicates via stdio using the MCP protocol.

## Security Notes

- SSL certificate verification is disabled by default for local development
- Ensure your MISP API key has appropriate permissions
- Use HTTPS in production environments
6. "What are the current MISP statistics?"
7. "Get information about recent MISP feeds"
8. "Perform an advanced search for TLP:RED events related to banking trojans"

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

