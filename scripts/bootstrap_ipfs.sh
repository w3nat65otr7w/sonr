#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# check if ~/.ipfs exists, if not create it
if [ ! -d ~/.ipfs ]; then
  ipfs init
  setup_ipfs
  start_ipfs
else
  start_ipfs
fi

function setup_ipfs() {
  # Optimize local discovery and connectivity
  ipfs config --json Discovery.MDNS.Enabled true
  ipfs config --json Routing.Type "dhtclient"
  ipfs config --json Swarm.ConnMgr.LowWater 200
  ipfs config --json Swarm.ConnMgr.HighWater 500

  # Set up the Cloudflare IPFS gateway peers
  ipfs config --json Peering.Peers '[
    {"ID": "QmcFf2FH3CEgTNHeMRGhN7HNHU1EXAxoEk6EFuSyXCsvRE", "Addrs": ["/dnsaddr/node-1.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcFmLd5ySfk2WZuJ1mfSWLDjdmHZq7rSAua4GoeSQfs1z", "Addrs": ["/dnsaddr/node-2.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfFmzSDVbwexQ9Au2pt5YEXHK5xajwgaU6PpkbLWerMa", "Addrs": ["/dnsaddr/node-3.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfJeB3Js1FG7T8YaZATEiaHqNKVdQfybYYkbT1knUswx", "Addrs": ["/dnsaddr/node-4.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfVvzK4tMdFmpJjEKDUoqRgP4W9FnmJoziYX5GXJJ8eZ", "Addrs": ["/dnsaddr/node-5.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfZD3VKrUxyP9BbyUnZDpbqDnT7cQ4WjPP8TRLXaoE7G", "Addrs": ["/dnsaddr/node-6.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfZP2LuW4jxviTeG8fi28qjnZScACb8PEgHAc17ZEri3", "Addrs": ["/dnsaddr/node-7.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfgsJsMtx6qJb74akCw1M24X1zFwgGo11h1cuhwQjtJP", "Addrs": ["/dnsaddr/node-8.ingress.cloudflare-ipfs.com"]},
    {"ID": "Qmcfr2FC7pFzJbTSDfYaSy1J8Uuy8ccGLeLyqJCKJvTHMi", "Addrs": ["/dnsaddr/node-9.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfR3V5YAtHBzxVACWCzXTt26SyEkxdwhGJ6875A8BuWx", "Addrs": ["/dnsaddr/node-10.ingress.cloudflare-ipfs.com"]},
    {"ID": "Qmcfuo1TM9uUiJp6dTbm915Rf1aTqm3a3dnmCdDQLHgvL5", "Addrs": ["/dnsaddr/node-11.ingress.cloudflare-ipfs.com"]},
    {"ID": "QmcfV2sg9zaq7UUHVCGuSvT2M2rnLBAPsiE79vVyK3Cuev", "Addrs": ["/dnsaddr/node-12.ingress.cloudflare-ipfs.com"]}
  ]'

  # Configure API and Gateway addresses to listen on localhost only
  ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
  ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080

  # Enable experimental features
  ipfs config --json Experimental.FilestoreEnabled true
  ipfs config --json Experimental.UrlstoreEnabled true
}

function start_ipfs() {
  # Start the IPFS daemon with additional options for better performance and compatibility
  ipfs daemon --enable-gc --migrate --enable-pubsub-experiment --enable-namesys-pubsub
}
