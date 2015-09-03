# burp-decompressor
An extension for BurpSuite used to access and modify compressed HTTP payloads without changing the content-encoding.

## Why this extension?
Often, HTTP traffic is compressed by the server before it is sent to the client in order to reduce network load.
Typically used algorithms are gzip or deflate. By default, BurpSuite will decompress all intercepted data in the body 
of HTTP messages in order to display plain text payloads in the different tabs and make stuff searchable. However, the
content is not recompressed back before it is sent to the browser. Usually, this isn't a problem.

In cases where the traffic is intended for other types of client instead of a browser, e.g. a fat/rich client using 
RMI over HTTP, the used content-encoding may sometimes be fixed and changing it will result in an error.

## What is it?
When using this extension, you will be able to access and modify compressed HTTP content in requests and responses
within a new tab in BurpSuite. The tab will appear as soon as compressed data is detected in a message body. For this,
you need to disable automatic unpacking of data by BurpSuite.

## How is it installed?
Launch BurpSuite, go to the Extender tab and then open the Extensions tab and click on "Add". In the dialog window,
select "java" as Extension Type and select the burp-decompressor.jar, that you can download from the [releases](https://github.com/antoinet/burp-decompressor/releases). For further details about BurpSuite extensions, refer
to their [documentation](https://portswigger.net/burp/help/extender.html#loading).

## How to disable automatic content decompression in BurpSuite?
In BurpSuite, open the Proxy tab, then the Options tab. Scroll to the bottom of the pane, under the title "Miscellaneous",
untick both "Unpack gzip / deflate in requests" and "Unpack gzip / deflate in responses".

## How do I build this shit?
Either use the build.xml with [ant](https://ant.apache.org), this will automatically download the latest free version
of BurpSuite to compile against. Or open the project in [Eclipe](http://www.eclipse.org/), create a lib directory and put
the burpsuite.jar in it, that you can download from [portswigger.net](https://portswigger.net/DownloadUpdate.ashx?Product=Free).


## Acknowledgements
This is my first BurpSuite extension, highly inspired by [federicodotta/BurpJDSer-ng-edited](https://github.com/federicodotta/BurpJDSer-ng-edited)
