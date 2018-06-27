# CHANGELOG

## `v0.2.0`

### Changes

* `NewS2STLS` constructor signature changes:
  * add a `clientCertificates []tls.Certificate`
  * replace `cert string` with `rootCA *x509.Certificate`
* Fixed the event time parsing. Expected format: `<UNIX time(s)>.<milliseconds>` (e.g. 1530024154.040)
