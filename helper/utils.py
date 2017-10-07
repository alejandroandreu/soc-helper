VALID_CONFIGURATIONS = [
    [ 'name', 'description', 'provider', 'baseurl' ],
    [ 'name', 'description', 'provider', 'apikey' ],
    [ 'name', 'description', 'provider' ]
]

MAX_CHECKS_COLS = 3

REGEX_IP = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
REGEX_URL = '^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$'
REGEX_FILE_HASH = "^([a-fA-F\d]+)$"