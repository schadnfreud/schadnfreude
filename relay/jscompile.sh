#!/bin/bash
cat index.html | sed 's/>/\n/g' | grep 'id="' | awk -F'id="' '{print $2}' | awk -F'"' '{print "var " $1 ";"}' > ids.txt
echo 'function jsQR(a,b,c,d){}' >> ids.txt
echo '/** @constructor */ function QRCode(a,b){this.a=a;}' >> ids.txt
# this little bit of renaming/wrapping means that while the original source stays the same, the minified JS code doesn't call "document..." a million times
# it just emits "const Aa = document" then calls "Aa..." a million times, which reduces overall size. Same for window, all the ID'd DOM elements, etc.
(
echo 'const dom_document = document;'
echo 'const dom_navigator = navigator;'
echo 'const dom_console = console;'
echo 'const dom_window = window;'
cat index.html | sed 's/>/\n/g' | grep 'id="' | awk -F'id="' '{print $2}' | awk -F'"' '{print "const dom_" $1 " = " $1 ";"}'
echo '(()=>{'
echo 'const document = dom_document;'
echo 'const navigator = dom_navigator;'
echo 'const console = dom_console;'
echo 'const window = dom_window;'
cat index.html | sed 's/>/\n/g' | grep 'id="' | awk -F'id="' '{print $2}' | awk -F'"' '{print "const " $1 " = dom_" $1 ";"}'
cat index.js
echo '})()'
) | tee deletme_generated.js | java -jar ../closure-compiler.jar --externs ./ids.txt -O ADVANCED --language_in ECMASCRIPT_2018 --language_out ECMASCRIPT_2018  > index.min.js
java -jar ../closure-compiler.jar --language_in ECMASCRIPT5 --language_out ECMASCRIPT5 < jsQR.js  > jsQR.min.js
