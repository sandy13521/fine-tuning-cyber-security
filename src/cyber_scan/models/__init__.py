from .openai_compatible import OpenAICompatibleClient

def create_client(config):
    if config.provider == "openai_compatible":
        return OpenAICompatibleClient(config)
    raise ValueError(f"Unsupported provider: {config.provider}")
