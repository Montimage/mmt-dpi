# Protocol Model

[TOC]

------------------


## Objectives

  * Speed up the creation of new plugins by partially/totally generating the protocol plugin code
  * Have an harmonized code all over the protocol plugins
  * ???
## What is a Protocol

For MMT, a protocol is a manager of a data block that can be encapsulated in a parent protocol (parent data block) and can encapsulate other protocols (child data block). A protocol is identified by:

  * ID: identifier that MUST be unique
  * Name: called also alias and MUST be unique
A protocol can have a number of properties like:

  * Encoding: It indicates how the protocol data block is encoded. It can be
    * Network: binary encoding with network byte ordering
    * Host: binary encoding with host byte ordering
    * ASCII: text based data encoding (like in log files)
    * RFC2822: Field-value based encoding (like HTTP)
    * RFC822: Internet text message format (like POP3, SMTP, etc.)
    * ???
  * Inner Encapsulation: It indicates if the protocol encapsulates other protocols.
  * Session maintainer: It indicates that the protocol maintains sessions. If this is the case, the protocol should provide how sessions are created, how they are cleaned.
  * Session context: It indicates that the protocol maintains a session context. Session context allows statefull analaysis of protocol data blocks belonging to the same session.
  * ???

A protocol can have a number of attributes

TBD

A protocol can have a classification mecanism: It tells the protocol how to identify the ecapsulated protocol. See classification function of IP protocol

A protocol can have a self classification mecanism: It tells parent protocol how to identify it. See `mmt_classify_me_xxx` function.


## Protocol Grammar

TBD

## Additional Readings

blablabla :)