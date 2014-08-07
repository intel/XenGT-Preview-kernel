README
======

Here is the experimental code to add Baytrail support in Intel gvt-g (previous
name XenGT). It is based on gvt-g latest patch release in 2014/07.

Here are the steps to get the code:

git clone git://kernel.ubuntu.com/ubuntu-archive/ubuntu-saucy.git
git checkout 549fad2377f797d330565a7a7669b478ba474091
patch -p1 < ./linux-vgt.patch
patch -p1 < ./byt-support-experiment.patch

Known issues
------------

1, Display DP support is not yet enabled.
2, There is no windows driver available for Baytrail gvt-g yet.

Contact
-------

"Lecluse, Philippe" <Philippe.Lecluse@intel.com>


Have fun!
