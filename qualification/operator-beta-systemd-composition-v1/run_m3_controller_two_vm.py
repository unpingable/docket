#!/usr/bin/env python3
"""Fixed 41-case controller-loss variant; not the ordinary 61-case matrix."""
import run_m3_two_vm as host

PRODUCER_HEAD = 'ff363e9a7be89b19eb8a4e9f1d8b5ab7547f45ef'
PRODUCER_TREE = 'd4b0f34c42afdf1583c2ac131ef81e42850027ce'

if __name__ == '__main__':
    host.main(controller=True, producer_head=PRODUCER_HEAD, producer_tree=PRODUCER_TREE)
