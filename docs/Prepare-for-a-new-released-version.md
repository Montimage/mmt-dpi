# Things need to be done before releasing a new stable version

## Update the new version number

Update the new version number in these files:

```
dist/ZIP/install.sh
rules/common.mk
src/mmt_core/public_include/mmt_core.h
```

## Verify the classification

```
cd mmt-test/wall_e
./walle -c wall-e.conf
```

Check the `.csv` report to see if there is any protocol that cannot be verified!

## Check the memory leak

Check the memory leak with `extract_all.c` and `probe` for those pcap files:

```
mmt-test/data-sets/memo/google-fr.pcap
mmt-test/data-sets/memo/bbc-com.pcap
mmt-test/data-sets/memo/366apps_7MB.pcap
mmt-test/data-sets/memo/84apps_120MB.pcap
mmt-test/data-sets/memo/65apps_360MB.pcap
```

Compare the result and fix the leaks if there is any

## Clean code

- Remove all log messages

- Update command for function/variable/ ...

- Remove unused source code/ files/ ...

## Set a tag for the new version

```
git tag -a v1.4 -m "my version 1.4"
```

Sharing tag:

```
git push origin v1.4
```

Checkout a tag:

```
git checkout -b new_branch_name v1.5
```

## Update the documents

- Update `ChangeLog`

- Update `changelog.html`

- Update `wiki`

---

Created by @luongnv89 on 12 July 2016
