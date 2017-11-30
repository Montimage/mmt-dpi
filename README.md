# MMT-DPI

A software C library desinged to extract data attributes from network packets, server logs, and from structured events in general, in odrder to make them available for analysis

[Wiki page for developer](https://bitbucket.org/montimage/mmt-sdk/wiki/Home)

## Todo list before releasing a new version

- Review all the changes in ChangLogs.md
- Update version number
- Check memory leaks with *Valgrind - memcheck*
- Check classification with *Walle*
- Static Code analysis with *PVS-Studio*
- Check with *mmt-probe*
- Update installation files (.deb, .zip, .rpm)
- Update documents:
    
    + Update wiki page for new APIs, tutorials, ...
    + list all protocol + attributes (GoogleDocs - sheet) - `src/examples/mmt_export_info.c`
    + MMT_Extract document: protocol categories
    + Update http://montimage.com/sdk/changelog.html

---
Website: [http://www.montimage.com](http://www.montimage.com)

Contact: [contact@montimage.com](mailto:contact@montimage.com)
