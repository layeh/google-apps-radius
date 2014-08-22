# google-apps-radius

This is a RADIUS server that authenticates against a Google Apps domain. The
authentication is done using a headless browser
as opposed to Google's deprecated [ClientLogin](https://developers.google.com/accounts/docs/AuthForInstalledApps).

## Usage

    Usage: google-apps-radius -p [port] -domain <domain> -secret <secret>

    Options:
      --domain  [required]
      --secret  [required]
      --port    [default: 1812]

## Known limitations

- Only supports RADIUS PAP (password authentication protocol)

## Author

Tim Cooper <<tim.cooper@layeh.com>>

## License

GPLv3