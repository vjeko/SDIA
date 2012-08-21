#!/usr/bin/python

from __future__ import print_function
from pyparsing import \
  Word, Literal, OneOrMore, ZeroOrMore, Suppress, Combine, Optional, \
  Group, \
  alphas, nums, printables

import re
import string

external = \
  Suppress(
   Word('-' + nums ) + # UID
   Combine('=' + Word(printables)) # DNS
  )

internal = \
  (
    Word( nums ).setResultsName('uid') +
    ( Word(printables) ).setResultsName('location') +
    Suppress( Optional('+') ) +
    Suppress( Optional('bb') ) +
    Suppress( Word('(' + nums + ')') ).setResultsName('neigh_num') +
    Suppress( Optional( Word('&' + nums) ) ).setResultsName('num_ext') +
    Suppress( "->" ) +
    Group(
      ZeroOrMore( Combine(Suppress('<') + Word(nums) + Suppress('>')))
    ).setResultsName('neigh') +
    Suppress(
      ZeroOrMore( Combine('{' + '-' + Word(nums) + '}') )
    ).setResultsName('ext', True) +
    Suppress( Combine('=' + Word(printables)) ).setResultsName('dns') +
    Suppress( Combine('r' + Word(nums)) ).setResultsName('hops')
    
  )

grammar = internal | external
pop = {}
v_loc_map = {}
edges = set()
loc_edges = set()


def parse_data():
  file = open("rocketfuel_maps_cch/7018.r0.cch")

  while True:
      line = file.readline()
      if not line: break

      result = grammar.parseString( line )
      if not len(result): continue

      src = result.get('uid')
      location = result.get('location')
      neigh = result.get('neigh')

      location = filter(str.isalnum, location)
      if location not in pop: pop[location] = set()
      pop[location].add(src)
      v_loc_map[src] = location

      for dst in neigh:
        edge = tuple(sorted([src, dst]))
        edges.add( edge )
 


def print_graph():
  print('graph {')
  for edge in edges:
    link = '\t%s -- %s' % (edge[0], edge[1])
    print(link)
  print('}')



def print_pops():
  for (key, value) in pop.items():
    key_string  = '"%s"' %(key)
    print(key_string, ' = {', sep = '', end = '')
    if not value: continue
    asn = value.pop()
    asn_string  = '"%s"' %(asn)
    print(asn_string, sep = '', end = '')
    for asn in value:
      asn_string  = '"%s"' %(asn)
      print(', ', asn_string, sep = '', end = '')
    print('}')



def print_contracted():
  for (src, dst) in edges:
    src_loc = v_loc_map[src]
    dst_loc = v_loc_map[dst]
    if src_loc == dst_loc: continue
    edge_loc = tuple(sorted([src_loc, dst_loc]))
    loc_edges.add( edge_loc) 

  print('graph {')
  for (src_loc, dst_loc) in loc_edges:
    link = '\t"%s" -- "%s"' % (src_loc, dst_loc)
    print(link)
  print('}')

parse_data()
#print_graph()
#print_pops()
print_contracted()
