# Guides

Comprehensive guides for installing, developing, and deploying MMT-DPI.

## Quick Links

| Guide | Description |
|-------|-------------|
| [Installation](installation.md) | Build and install on Linux, macOS, Windows |
| [Development](development.md) | Development workflow and testing |
| [Adding Protocols](adding-protocols.md) | Create custom protocol handlers |
| [Deployment](deployment.md) | Production deployment considerations |

## Getting Started Path

```mermaid
flowchart LR
    INSTALL[Installation] --> DEV[Development]
    DEV --> PROTO[Adding Protocols]
    PROTO --> DEPLOY[Deployment]
```

1. **[Installation](installation.md)** - Get MMT-DPI built and running
2. **[Development](development.md)** - Set up your development environment
3. **[Adding Protocols](adding-protocols.md)** - Extend with custom protocols
4. **[Deployment](deployment.md)** - Deploy in production
