import configparser

class SHConfig:
    def __init__(self, path):
        self.path = path
        self.config = configparser.ConfigParser()
        try:
            self.config.read(self.path)
        except configparser.Error:
            print("File {} doesn't seem to be a valid configuration file".format(self.path))
            print("Supported file structure: https://docs.python.org/3/library/configparser.html#supported-ini-file-structure")

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
