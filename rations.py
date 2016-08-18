#!/bin/python
#=================================================================================
#
# FILE: rations.py
#
# DESCRIPTION:
# https://www.hackerrank.com/challenges/fair-rations?h_r=next-challenge&h_v=zen
# 
# AUTHOR: Cary Williams
# CREATED: 2016-08-17
#=================================================================================


import sys


N = int(raw_input().strip())
B = map(int,raw_input().strip().split(' '))

def rations(N, B):
    iter = 0
    if (sum(B) % 2):
        print("NO")
    else:
        for i in range(len(B) - 1):
            if B[i] % 2:
                B[i + 1] = B[i + 1]
                iter += 2
        print iter

rations(N, B)
