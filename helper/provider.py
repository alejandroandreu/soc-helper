import configparser
import utils

def create(pc):
    provider_type = pc.config.get(pc.config.sections()[0], "Provider")
    switcher = {
            "SimpleProvider": SimpleProvider(pc)
            }
    return switcher.get(provider_type)


class ProviderException(Exception):
    """Basic exception for errors raised by providers"""
    pass

class ProviderConfigException(ProviderException):
    """Raised when a provider configuration file is wrong"""
    # TODO: Print which file is wrong
    pass

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
        print(path)
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
