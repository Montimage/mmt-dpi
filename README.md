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
    
    + Wiki page for new APIs, tutorials, ...
    + List all protocol + attributes [GoogleSheet](https://docs.google.com/spreadsheets/d/10ircpIPJEEvZ5eUzwG5vY6YOw07kw6btzoDNTg3cMPU/edit?usp=sharing) - by compile and run `src/examples/mmt_export_info.c`
    + MMT Classification document [GoogleDocs](https://docs.google.com/document/d/1aLf_Jf27RJt_z99XUqtHWseqcWu0G5g2iAZzjVhpnek/edit?usp=sharing)
    + `changelog.html` and publish on http://www.montimage.com/sdk/changelog.html

---
Website: [http://www.montimage.com](http://www.montimage.com)

Contact: [contact@montimage.com](mailto:contact@montimage.com)
