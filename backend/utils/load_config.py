import yaml
import os
import secrets
import logging

logger = logging.getLogger(__name__)

# Cache the configuration to avoid reloading on every request
_config_cache = None


def load_config():
    """
    Load configuration from YAML file and override sensitive values from environment variables.

    Environment variables take precedence over config file values for security.
    Configuration is cached to avoid regenerating secrets on every call.
    """
    global _config_cache

    # Return cached config if already loaded
    if _config_cache is not None:
        return _config_cache

    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.normpath(os.path.join(base_dir, '..', '..', '.config', 'config.yaml'))

    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    # Override sensitive values from environment variables

    # 1. API Keys (CRITICAL-01 fix)
    if 'threat_detection' in config:
        # VirusTotal API key
        vt_key_env = os.getenv('VIRUSTOTAL_API_KEY')
        if vt_key_env:
            config['threat_detection']['virustotal_api_key'] = vt_key_env

        # Hybrid Analysis API key
        ha_key_env = os.getenv('HYBRID_ANALYSIS_API_KEY')
        if ha_key_env:
            config['threat_detection']['hybrid_analysis_api_key'] = ha_key_env

    # 2. JWT Secret (CRITICAL-02 fix)
    if 'security' not in config:
        config['security'] = {}

    jwt_secret_env = os.getenv('JWT_SECRET')
    if jwt_secret_env:
        config['security']['jwt_secret'] = jwt_secret_env
    else:
        # Validate existing secret
        current_secret = config['security'].get('jwt_secret', '')
        if not current_secret or current_secret == 'change-me-please' or len(current_secret) < 32:
            # Generate strong secret
            new_secret = secrets.token_urlsafe(64)
            config['security']['jwt_secret'] = new_secret
            logger.warning(
                "SECURITY WARNING: Weak or missing JWT secret detected. "
                "Generated a new secure secret. Please set JWT_SECRET environment variable "
                "or update config.yaml with a strong secret (32+ characters)."
            )

    # 3. CSRF Secret
    csrf_secret_env = os.getenv('CSRF_SECRET')
    if csrf_secret_env:
        config['security']['csrf_secret'] = csrf_secret_env
    elif 'csrf_secret' not in config.get('security', {}):
        config['security']['csrf_secret'] = secrets.token_urlsafe(32)

    # Cache the configuration
    _config_cache = config

    return config