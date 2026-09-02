# MMT-DPI Documentation #

Documentation for the MMT-DPI deep packet inspection library. For a project
overview and quick start, see the [root README](../README.md).

## Getting Started ##
* [User Guide](./USER_GUIDE.md) — install, first run, and embedding the library
* [Compilation and Installation Instructions](./Compilation-and-Installation-Instructions.md)
* [Compiling for ARM (cross-compiler)](./Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md)
* [Examples](./Examples.md)
    * [MMT QoE demo](./MMT-QoE-demo.md)

## Architecture & Internals ##
* [Architecture](./ARCHITECTURE.md) — modular plugin design and packet-processing flow
* [Threading Model](./THREADING.md) — initialization ordering and the lock-free hot path
* [Global Handler](./Global-Handler.md)
* [MMT Handler](./MMT-Handler.md)
* [MMT Packet](./MMT-Packet.md)
    * [Packet Journey](./Packet-Journey.md)
* [MMT Session](./MMT-Session.md)
* [MMT Attributes](./MMT-Attributes.md)
    * [Attribute Conditions](./Attribute-Conditions.md)
* [Data Types](./Data-Types.md)
* [Memory Management](./Memory-Management.md)

## Protocols ##
* [MMT Protocol](./MMT-Protocol.md)
    * [Protocol Statistics](./Protocol-Statistics.md)
    * [Protocol Modeling](./Protocol-Modeling.md)
    * [Adding a New Protocol](./Add-New-Protocol.md)
* [Protocol Stack](./Protocol-Stack.md)
* [Phase-2 Heuristics](./Phase2-Heuristics.md)

## Development & Operations ##
* [Agent Environment Notes](./AGENT_ENVIRONMENT.md) — toolchain, build/test commands of record, `MMT_BASE`, sanitizer profiles, `ENABLESEC`
* [Development](./DEVELOPMENT.md) — local setup, build options, testing, debugging
* [Developer Notes](./Developer.md) — entry point for extending MMT-DPI and per-protocol docs
* [Deployment](./DEPLOYMENT.md) — install layout, linking, runtime environment
* [Deployment Considerations](./Deployment-Consideration.md)
* [Preparing a New Release](./Prepare-for-a-new-released-version.md)
* [Discussion Points](./Discussion-Points.md) — design notes and open questions
* [Exported Symbols](./Exported-Symbols.md) — full public API symbol reference
* [Troubleshooting](./troubleshooting.md)

## Additional References ##
* [ChronoChat](./ChronoChat.md) — ChronoChat protocol notes
* [External Attribution](./External-Attribution.md) — third-party attributions
