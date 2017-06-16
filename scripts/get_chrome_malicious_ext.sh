#!/bin/bash

set -e
set -x

curl  https://cs.chromium.org/codesearch/f/chromium/src/content/browser/download/download_stats.cc?cl=master | grep FILE_PATH_LITERAL\( | cut -d'"' -f 2 | \
    tr '\n' '#' | \
    sed -r 's/([[:alnum:]_-.]*)#/, "\1"/g' # > google_ext.txt
