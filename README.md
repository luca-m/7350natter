7350natter
==========

Published for historical reasons, as such bad injection boxens seem to be used
more widespread in 2018. So that you can get the basic idea on
how you would detect from inside that you are locked in the matrix network.

It was helpful at times.

Warning: dirty code. I wrote this somewhere 200x, and there was
no IP6 to test with. So, I would need to add that part, as well as more
cleanups and beautifications. No `unique_ptr` or all the other fancy
stuff yet.

The basic idea is to trace-route the path to the destination with
ICMP, which is not tampered by the boxes, and use that minimum TTL
to compare with TCP connects, which succeeds with a lower TTL
if there is such a box on the path.

There may exist variants :)


Natter is a german word for some kind of snakes and derived from NAT
or NAT-checker, as the evil boxes did some kind of unwanted NAT.

