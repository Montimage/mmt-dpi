# FTP protocol

## Overview

**Working branch:** ftp

**Started date:** 21/09/2015

**Deadline:** 26/10/2015

**Developer:** @luongnv89

**Probe example**: reconstruct file content and extract file information such as: MIME/Type, size, name, ...

## List of tasks

* Study about protocol -> understand packet format specification/ how to classify protocol -> OK

* Create data struct for extracting protocol attributes -> OK

* Study some open-source library (if it exists) to see how do they do -> OK

* Implement classify FTP packet -> OK

* Implement parse FTP packet data -> OK

* Test FTP plugin -> OK

* Merge to MMT-SDK -> Waiting for fixing libntoh

## Contents

[Structure design](/montimage/mmt-sdk/wiki/FTP%20design)

[Test case](/montimage/mmt-sdk/wiki/FTP%20test%20case)

[Documents](/montimage/mmt-sdk/wiki/FTP%20documents)
