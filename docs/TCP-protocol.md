---
layout: default
title: "TCP protocol"
---

# TCP protocol

## Overview

MMT-DPI classifies TCP and extracts its attributes. TCP stream reassembly —
reconstructing the payload content of a flow — is built on the integrated
`libntoh` engine, allowing a probe to recover the full data payload and extract
all attributes across reordered or overlapping segments.

## Contents

[Design](./TCP-design.md)

[Test case](./TCP-test-case.md)

[Documents](./TCP-documents.md)