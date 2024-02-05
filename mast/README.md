# Mast

In this crate, we build an [mast](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) tree that supports threshold multi-signature

## Conceptual Overview
This module implements Mast by transforming the Merkle tree. Mast uses Schnorr aggregated public keys as leaf nodes.

In order to achieve the threshold signature of m-of-n, the combined number $\binom{n}{m}$ aggregated public keys 
are used as leaf nodes to achieve the threshold signature of m-fo-n. In order to solve the problem of rapid mast 
expansion when n is too large, the current preliminary solution is to prune the mast tree.
