This is a fork of this bzr repository http://wilmer.gaa.st/selphy/ from Wilmer van der Gaast (@Wilmer in twitter).

It's basically a Go program to send pictures to a Canon Selphy CP900 printer connected via wifi. This at least lets you print from OSX because Canon does not provide drivers for latest versions the Apple OS.

Check the [original README](README.old) for more info about it.

I added the binary for Yosemite in case you don't want to build it yourself.

I tried to print a picture checking the printer IP from the router info page like this:
```
./selphy -printer_ip="192.168.1.133" ~/Pictures/print-01.jpg
```

And worked great, so thanks Wilmer! ;-)
