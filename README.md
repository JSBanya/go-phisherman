# PhisherMan Install Guide and Usage

## Information
PhisherMan is an experimental project for detecting phishing websites based on image similarity detection. Websites that are visited are used to create a fingerprint, which is then checked for similarities with known websites to determine the probability of phishing. Websites deemed safe are added to a database for future comparison. 

PhisherMan is designed to be installed as an application-level proxy and will work over both HTTP and HTTPs. For HTTPs functionality, a root certificate must be generated and installed in a browser (see below) or MITM warnings will appear. For sites using HTTPs, PhisherMan will self-sign a certificate for the target website. This is effectively a working implementation of a MITM attack and is done so that PhisherMan can inspect the (otherwise encrypted) website contents.

Important: PhisherMan is NOT production-ready. This is a research project to determine the effectiveness of certain detection algorithms in relation to phishing attacks.

## Dependencies needed for PhisherMan:
Please make sure you have installed the following software packages before proceeding:
* golang (https://golang.org/)
* wkhtmltoimage (https://wkhtmltopdf.org/)


## How to build PhisherMan:
PhisherMan can be easily built using the provided Makefile. Just run the following commands:
```
$ make fetch
$ make
```

## How to initialize PhisherMan:
PhisherMan's root certificate must be created before PhisherMan can be used:
```
$ ./init_rootca.sh
```
Then, install the root certificate (rootCA.crt) into your browser under the "Authorities" tab.

Be sure to check the box to "Trust this certificate for identifying websites"

## How to run PhisherMan:
```
$ ./phisherman [PORT]
```
Then, launch the web browser you installed the certificate into and configure it to use PhisherMan's proxy on the specified port (or the default 52078).

You may also prefer to use incognito or private browsing mode for testing as you will likely be visiting a bunch of phishing sites.

This can be easily accomplished with chrome/chromium in one command:
```
$ chromium-browser --incognito --proxy-server=localhost:52078
```
