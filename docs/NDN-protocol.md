# NDN protocol

## Overview

**Working branch:** ndn

**Started date:** ---

**Deadline:** ---

**Developer:** @luongnv89

**Probe example**:

## List of tasks

* Study about protocol -> understand packet format specification/ how to classify protocol - **DONE**

* Create data struct for extracting protocol attributes  - **DONE**

* Study some open-source library (if it exists) to see how do they do  - **NO NEED**

* Implement classify NDN packet  - **DONE**

* Implement parse NDN packet data  - **DONE**

* Test NDN plugin  - **DONE**

* Merge to MMT-SDK - **DONE**

## View NDN packet in Wireshark

To view NDN packet in Wireshark application:

* Download script to ndn: `mmt-test/scripts/ndn.lua`

* Run wireshark from terminal with command: `wireshark -X lua_script:ndn.lua`

## Contents

[NDN packet format](/montimage/mmt-sdk/wiki/NDN%20packet%20format)

[Structure design](/montimage/mmt-sdk/wiki/NDN%20design)

[Test case](/montimage/mmt-sdk/wiki/NDN%20test%20case)

[ChronoChat application](/montimage/mmt-sdk/wiki/chronochat)

[Documents](/montimage/mmt-sdk/wiki/NDN%20documents)
