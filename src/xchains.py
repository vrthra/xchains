#!/usr/bin/env python

import sys
import os
import time
import angr
import random
import claripy
from ptpython.repl import embed

Max_Input_Len = int(os.environ.get('MAX_INPUT', '100'))
Success_Fn = os.environ.get('SUCCESS_FN', 'success')
Random_Seed = int(os.environ.get('R', '0'))
random.seed(Random_Seed)

def w(v): sys.stderr.write(v); sys.stderr.flush()
def log(v): w("\t%s\n" % v)

class Program:
    def __init__(self, exe, input_len):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        self.success_fn = self.get_fn_addr(Success_Fn)
        self.input_len = input_len

        # generate arg1 from individual characters.
        self.arg1 = self.update_args(self.input_len, prefix='sym_arg')

        # we use the argv[1] as the input.
        self.initial_state = self.project.factory.entry_state(args=[exe, self.arg1])

        # make sure that we try a maximum of input_Len chars
        self.initial_state.add_constraints(self.arg1a[self.input_len] == 0)
        # and we have sufficient constraints for minimal length
        for i in range(self.input_len):
            self.initial_state.add_constraints(self.arg1a[i] != 0)

    def dfs(self):
        sm = self.project.factory.simulation_manager(self.initial_state)
        sm.use_technique(angr.exploration_techniques.DFS())
        res = sm.explore(find=self.success_fn)
        return res

    def is_successful(self, state):
        return self.success_fn == state.addr

    def get_constraint_range(self, state):
        return [self.mmx(state, c) for c in self.arg1a]

    def update_args(self, input_len, prefix):
        """
        Various mappings to argument chars for easy access.
        Note that claripy.BVS('sym_arg', 8 * N) is equivalent
        to reduce(lambda x,y: x.concat(y), self.arg1a), but it
        gives us better access to individual elements
        """
        largs = range(input_len+1)
        arg1k = ['%s_%d' % (prefix, i) for i in largs]
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        return reduce(lambda x,y: x.concat(y), self.arg1a)

    def retrieve_vars_in_constraints(self, state):
        return [state.solver.variables(c) for c in state.solver.constraints]

    def is_printable(self, state, i):
        m, n = self.range_at(state, i)
        return m > 31 and n < 128

    def get_fn_addr(self, fname):
        self.cfg = self.project.analyses.CFG(fail_fast=True)
        functions = self.cfg.kb.functions
        found = [addr for addr,f in functions.iteritems() if fname == f.name]
        assert len(found) == 1, "No address found for function : %s" % fname
        return found[0]

    def mmx(self, state, c): return (state.solver.min(c), state.solver.max(c))
    def range_at(self, state, at): return self.mmx(self.arg1a[at])

    def choose_a_successor_state(self, states):
        return pop_random(states)

    def choose_a_previous_path(self, states):
        state, states = self.pop_smallest(states)
        return state, states

    def get_constraint_change(self, pstate, state):
        parent_constraint_range = self.get_constraint_range(pstate)
        pconstraints = pstate.solver.constraints
        child_constraint_range = self.get_constraint_range(state)
        _min, _max = 0, 1
        console = False
        for i, (p,c) in enumerate(zip(parent_constraint_range, child_constraint_range)):
            #if not p[_min] <= c[_min]: console = True
            #if not p[_max] >= c[_max]: console = True
            pc = pstate.solver.constraints
            assert pc == pconstraints
            #if console:
            #    console = False
            #    print p, c
            #    x = self.get_constraint_range(pstate)
            #    embed(globals(), locals())
            if p != c: return i # constraints only narrow
        return None

    def gen_chains(self, state):
        states = []
        pstate = None
        while True:
            if self.is_successful(state): return ('success',state)
            # successors for symbolic
            flat_successors = state.step().flat_successors
            my_successors = [(state, s) for s in flat_successors]
            nsucc = len(my_successors)
            if nsucc == 1:
                # constraints will not change here unless ASSERT is there.(TODO)
                pstate, state = my_successors.pop()
                # print ">>>>", pstate, state
                continue
            elif nsucc == 0:
                # No active successors.
                if not states: return ('no_states', None)
                log("<< %d(" % len(states))
                (pstate, state), states = self.choose_a_previous_path(states)
            elif nsucc > 1:
                (pstate, state), ss = self.choose_a_successor_state(my_successors)
                states.extend(ss)
            else: assert False
            w("%s [%s]" % (repr(self.get_args(pstate)), self.str_len(pstate)))

            # were there any new chars?
            idx = self.get_constraint_change(pstate, state)
            if idx is not None:
                self.extra_states.extend(states)
                # commit to the state
                states = []
                w("\t@%d: %s" % (idx, chr(state.solver.eval(self.arg1a[idx]))))
            log('')

    def get_args(self, state):
        #return state.solver.eval(self.arg1, cast_to=str)[0:self.last_char_checked+1]
        val = state.solver.eval(self.arg1, cast_to=str)
        for i in range(len(val)):
            if val[i] == '\x00':
                return val[0:i]
        return val

    def print_args(self, state):
        for i in state.solver.eval_upto(self.arg1, 10, cast_to=str):
            log(repr(i)) #.strip('\x00\xff')))

    def pop_last(self, arr):
        i = arr.pop()
        return i, arr

    def pop_random(self, arr):
        i = arr.pop(random.randint(0, len(arr)-1))
        return i, arr

    def pop_smallest(self, arr):
        res = sorted([(self.str_len(a[1]), i) for i,a in enumerate(arr)])
        idx = res[0][1]
        i = arr.pop(idx)
        return i, arr

Show_Range = False
def main(exe):
    status, state = None, None
    with open("results.txt", "w+") as f:
        for i in  range(Max_Input_Len):
            print ">>",i
            prog = Program(exe, i)
            state = prog.initial_state
            sm = prog.dfs()
            for s in sm.found:
                prog.print_args(s)
main(sys.argv[1])
