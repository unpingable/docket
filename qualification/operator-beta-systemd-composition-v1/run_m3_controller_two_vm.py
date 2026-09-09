#!/usr/bin/env python3
"""Fixed 41-case controller-loss variant; not the ordinary 61-case matrix."""
import run_m3_two_vm as host

PRODUCER_HEAD = 'UNFROZEN'
PRODUCER_TREE = 'UNFROZEN'

if __name__ == '__main__':
    host.main(controller=True, producer_head=PRODUCER_HEAD, producer_tree=PRODUCER_TREE)
