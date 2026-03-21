from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # LLM — default to Claude (Anthropic)
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""
    LLM_PROVIDER: str = "anthropic"  # "anthropic" | "openai" | "google"
    LLM_MODEL: str = "claude-sonnet-4-6"

    # MISP
    MISP_URL: str = "https://misp.local"
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = False

    # OpenSearch
    OPENSEARCH_URL: str = "http://localhost:9200"
    OPENSEARCH_USE_SSL: bool = False
    OPENSEARCH_VERIFY_CERTS: bool = False
    OPENSEARCH_USERNAME: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"

    # External enrichment (all free tier)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""

    # Vector store
    CHROMA_DB_PATH: str = "./soc_agent/data/chroma_db"
    EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"

    # Agent execution
    MAX_ITERATIONS: int = 15
    INVESTIGATION_DB_PATH: str = "./soc_agent/data/investigations.db"

    # Paths
    MISP_MCP_SERVER_PATH: str = "./misp_mcp_server.py"
    MITRE_STIX_PATH: str = "./soc_agent/data/mitre_attack_v14.json"
    PLAYBOOKS_DIR: str = "./soc_agent/playbooks"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
