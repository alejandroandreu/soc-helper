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
    elif provider_type == "SnapitoProvider":
        return SnapitoProvider(pc)
    else:
        raise ProviderException


class ProviderException(Exception):
    """Basic exception for errors raised by providers"""
    pass

class VTProviderException(ProviderException):
    """Raised when there is an error obtaining the final VirusTotal URL"""
    pass

class ProviderConfigException(ProviderException):
    """Raised when a provider configuration file is wrong"""
    # TODO: Print which file is wrong
    pass

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
            raise VTProviderException
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
            raise ProviderConfigException
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

        raise ProviderConfigException
