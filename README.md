# OvalTools
> Utility code to make OVAL files useful

## What?
`ovaltools` is a python library for parsing platform-specific OVAL files. It was created out of a desire to get information about the ubiquity of a given Ubuntu Security Notice vulnerability (and need for package upgrade) across an infrastructure without having to run `openscap` on each host (which is expensive) and rather just parse a `dpkg` listing for each host.

Currently it only works for Ubuntu, and (very likely) only `bionic` (18.04) because I suspect that the format *may* be different for other releases (although I've not verified yet)

## How do I even?
This library isn't even minimal viable product yet, so the best way to try and get your head around it is to have a look at the tests. There are two main objects you need to concern yourself with: `UbuntuOval` and `Inventory`. The `UbuntuOval` object represents the vulnerability information contained in the OVAL XML file, and the `Inventory` represents a given host. 

You can feed an `Inventory` object the output of:

```
dpkg-query --showformat='${Package} ${Version}\n' --show
```

using:

```
from ovaltools.inventory import Inventory
i = Inventory('some.host.com')
# Some fictional host that only has `unbound` installed - dpkg_output would *actually* be your `dpkg-query` output as above
dpkg_output = "unbound 1.6.7-1ubuntu2.0\n"
i.ingest_dpkg(dpkg_output)
```

... and you'd pull in the oval file and process the host like so:

```
u = UbuntuOval('some.oval.file.xml')
i.process(u)
```

`i.vulnerable_to_refs` will now be populated with a dict of the format `{oval_ref_number: [vulnerable_package, ...]}`

I've not done the work yet to translate these reference numbers (or `ref`s) back to vulnerabilities, but it's not a lot of work.

## Helpful stuff
There are a few helpful `make` targets:

```
get_oval: will fetch the latest `bionic` oval file
test: will run the tests
test_skipslow: will run all but the tests marked as `slow`
```
