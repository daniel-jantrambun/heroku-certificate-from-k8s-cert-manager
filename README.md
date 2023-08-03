# HEROKU TLS INSTALL

Get TLS certificate from GCP kubernetes cluster and install them on Heroku apps

Steps:

- get TLS in kubernetes secret
- check if heroku app has a certificate with the same `Common Name`
- If no, install the certificate on heroku app
- If Yes, compare the ExpiresOn date on both certificates and if not equal, install the new certificate on Heroku app.
