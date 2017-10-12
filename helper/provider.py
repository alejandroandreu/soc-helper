import requests
import configparser
import utils
from urllib.parse import urlparse, quote_plus

def create(pc):
    provider_type = pc.config.get(pc.config.sections()[0], "Provider")
    if provider_type == "SimpleProvider":
        return SimpleProvider(pc)
    elif provider_type == "VirusTotalUrlProvider":
        return VirusTotalUrlProvider(pc)
    elif provider_type == "VirusTotalFileProvider":
        return VirusTotalFileProvider(pc)
    elif provider_type == "SnapitoProvider":
        return SnapitoProvider(pc)
    else:
        raise ProviderConfigError(pc,
            "{pcp}: {pt} is not a valid provider type".format(pcp=pc.path,pt=provider_type))


class ProviderError(Exception):
    """Basic exception for errors raised by providers"""
    def __init__(self, provider, msg=None):
        if msg is None:
            msg = "An error ocurred with provider {}".format(provider)
        super(ProviderError, self).__init__(msg)
        self.provider = provider

class VirusTotalError(ProviderError):
    """Raised when there is an error obtaining the final VirusTotal URL"""
    def __init__(self, provider, res, query):
        super(VirusTotalError, self).__init__(
            provider,
            msg="Error retrieving report from VirusTotal for {res}: {query}".format(res=res, query=query))
        self.resource = res
        self.query = query

class ProviderConfigError(Exception):
    """Raised when a provider configuration file is wrong"""
    def __init__(self, provider_config_path, msg=None):
        if msg is None:
            msg = "An error ocurred with provider configuration {}".format(provider_config_path)
        super(ProviderConfigError, self).__init__(msg)
        self.provider_config_path = provider_config_path

class VirusTotalFileProvider:
    """
    Provider that leverages the VirusTotal API to analyze a URL
    """
    def __init__(self, pc):
        self.type = "complex"
        self.name = pc.config.get(pc.config.sections()[0], "Name")
        self.description = pc.config.get(pc.config.sections()[0], "Description")
        self.provider = pc.config.get(pc.config.sections()[0], "Provider")
        self.api_key = pc.config.get(pc.config.sections()[0], "ApiKey")
        self.base_url = 'https://www.virustotal.com/vtapi/v2/file/report'

    def get_url(self, file_hash):
        vt_params = { 'apikey': self.api_key, 'resource': file_hash }
        try:
            response = requests.post(self.base_url, params=vt_params)
            json_response = response.json()
        except:
            raise VirusTotalError(self, "file hash", file_hash)
        return json_response['permalink']

class VirusTotalUrlProvider:
    """
    Provider that leverages the VirusTotal API to analyze a URL
    """
    def __init__(self, pc):
        self.type = "complex"
        self.name = pc.config.get(pc.config.sections()[0], "Name")
        self.description = pc.config.get(pc.config.sections()[0], "Description")
        self.provider = pc.config.get(pc.config.sections()[0], "Provider")
        self.api_key = pc.config.get(pc.config.sections()[0], "ApiKey")
        self.base_url = 'https://www.virustotal.com/vtapi/v2/url/report'

    def get_url(self, url):
        vt_params = { 'apikey': self.api_key, 'resource': url }
        try:
            response = requests.post(self.base_url, params=vt_params)
            json_response = response.json()
        except:
            raise VirusTotalError(self, "URL", url)
        return json_response['permalink']

class SnapitoProvider:
    """
    Provider to get screenshots of URLs
    """
    def __init__(self, pc):
        self.type = "complex"
        self.name = pc.config.get(pc.config.sections()[0], "Name")
        self.description = pc.config.get(pc.config.sections()[0], "Description")
        self.provider = pc.config.get(pc.config.sections()[0], "Provider")

    def get_url(self, url):
        return "https://snapito.com/screenshots/{domain}.html?size=800x0&screen=1024x768&cache=2592000&delay=-1&url={encoded_url}".format(
                domain = urlparse(url).netloc,
                encoded_url = quote_plus(url)
                )


class SimpleProvider:
    """
    A.K.A. URL providers, which do not need any kind of authentication
    or calls made to an API.
    """
    def __init__(self, pc):
        self.type = "simple"
        self.name = pc.config.get(pc.config.sections()[0], "Name")
        self.description = pc.config.get(pc.config.sections()[0], "Description")
        self.provider = pc.config.get(pc.config.sections()[0], "Provider")
        self.base_url = pc.config.get(pc.config.sections()[0], "BaseUrl")

    def get_url(self, arg):
        return self.base_url.replace('$$ARG$$', arg)

class ProviderConfig:
    """
    Loads and validates a provider configuration file. If the file does
    not exist or the configuration is incorrect a ProviderConfigException
    is raised.
    """
    def __init__(self, path):
        self.path = path
        self.config = configparser.ConfigParser()
        try:
            self.config.read(self.path)
        except configparser.Error:
            raise ProviderConfigError(self.path)
        self.validate()

    def keys(self):
        keys = []
        for section in self.config.sections():
            for item in self.config.items(section):
                key = item[0]
                if key not in keys:
                    keys.append(item[0])
        return keys

    def print(self):
        for section in self.config.sections():
            print("[{}]".format(section))
            for key, value in self.config.items(section):
                print("{key} = {value}".format(key=key, value=value))

    def validate(self):
        for config in utils.VALID_CONFIGURATIONS:
            lowercase_keys = [key.lower() for key in self.keys()]
            if set(lowercase_keys) == set(config):
                return True
        raise ProviderConfigError(self.path,
            "Provider configuration at {} doesn't seem to be valid.".format(self.path))

    def __str__(self):
        return self.path
