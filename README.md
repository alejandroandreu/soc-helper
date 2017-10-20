# SOC Helper

SOC Helper is a simple utility that aims to save precious
intelligence-gathering analyst time by querying certain websites with the user
input. Currently it supports:

* IP addresses
* URLs
* Domains
* File hashes

## Requirements

The following Python 3 dependencies are required in order to run the project
from source:

```
PyQt5
requests
```

If you do not wish to install Python and these requirements please head over to
the [Releases](https://github.com/alejandroandreu/soc-helper/releases) page and
download the binaries for your operating system.

## Providers

SOC Helper is extensible so you can adapt it to your needs. Have an in-house
knowledge base that you want to query? No problem! Add your own configuration
file and SOC Helper will do that for you.

There are two types of providers, *simple* and *complex*. Simple providers
build a URL by placing the user input somewhere in a request. For instance,
when querying 8.8.8.8 on AbuseIPDB the URL looks like the following:

```
https://www.abuseipdb.com/check/8.8.8.8
```

As you can see, just appending the IP to the base URL is enough. Complex
providers however do more stuff, like querying an API to obtain the final URL.

All provider configuration files are placed inside the `providers` folder, which
must be located in the same base folder than the SOC Helper executable file.

### Simple Provider

All simple providers are configured with a configuration file like the following:

```
[AbuseIPDB]
Name = AbuseIPDB
Description = AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks.
Provider = SimpleProvider
BaseUrl = https://www.abuseipdb.com/check/$$ARG$$
```

* `[AbuseIPDB]` (Mandatory) The identifier between brackets can be set to anything
* `Name` (Mandatory) is the name that will be displayed in the application
* `Description` (Optional) can be left blank
* `Provider` needs to be set to `SimpleProvider`
* `BaseUrl` can be any URL, and `$$ARG$$` will be replaced by the user's input

### Complex Provider

Complex providers do not include any `BaseUrl`, as these are hardcoded in the
implementation. A sample complex provider:

```
[VirusTotal]
Name = VirusTotal
Description = VirusTotal aggregates many antivirus products and online scan engines to check for viruses that the user's own antivirus may have missed, or to verify against any false positives.
Provider = VirusTotalFileProvider
ApiKey =
```

If the provider requires an API key to perform calls, you would need to fill the
`ApiKey` field too.

#### List of complex providers

* VirusTotalFileProvider
* SnapitoProvider
* VirusTotalUrlProvider
