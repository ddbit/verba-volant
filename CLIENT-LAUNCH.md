## TL;DR Quick launch

A [vv-client.zip](vv-client.zip) with the html/js/css code is available for a quick test. Uncompress and click on index.html

For a longer description read below.

## The client index.html

The client can be loaded via ```file://``` protocol. Save the the folder ```public``` in your computer and click on the index.html file. The client is a vanilla static page which loads his styles and his javascript. No other deps required. 

For a better experience I recommend to load index.html in a first browser window (which will be Alice) and then use a different browser or browser profile to load as Bob.

## HTTPS Issue

Check the issues on github project. At the moment the client [can't be served via ```http://```](https://github.com/ddbit/verba-volant/issues/1) because of browser restrictions that require ```https://``` protocol from remote loading.

Using Verba Volant without https **is not an issue** per sé, the whole system is designed to be resistant to observation and manipulation in compromised servers.