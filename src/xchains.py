#!/usr/bin/env python

from enum import Enum
import sys
import os
import time
import angr
import random
import claripy
from ptpython.repl import embed

# How to choose the next state. The Prob_Mul_Factor skews the
# probability distribution of choise of elements from the list
# of states. If greater than 0, it gives a slightly higher
# weightage to the later states. If it is 0, it is same as
# random sampling.
Prob_Mul_Factor = 0
Max_Input_Len = int(os.environ.get('MAX_INPUT', '100'))
Success_Fn = os.environ.get('SUCCESS_FN', 'success')
Random_Seed = int(os.environ.get('R', '0'))
random.seed(Random_Seed)
_min, _max = 0, 1
_parent, _child = 0, 1
# Given a range of solutions, should we fix one solution
# before we explore further?
Quick_Fix = True

class R(Enum):
    NO_STATES = 0
    SUCCESS = 1

def w(v):
    sys.stderr.write(v)
    sys.stderr.flush()

def log(v): w("\t%s\n" % v)

class Program:
    def __init__(self, exe):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        self.success_fn = self.get_fn_addr(Success_Fn)

    def get_fn_addr(self, fname):
        if 'cfg' not in self.__dict__:
            self.cfg = self.project.analyses.CFG(fail_fast=True)
        functions = self.cfg.kb.functions
        found = [addr for addr,f in functions.iteritems() if fname == f.name]
        assert len(found) == 1, "No address found for function : %s" % fname
        return found[0]

    def is_successful(self, state): return self.success_fn == state.addr

    def update(self, input_len, constraint_range, refused_range):
        self.input_len = input_len
        # generate arg1 from individual characters.
        self.arg1 = self.update_args(self.input_len, prefix='sym_arg')

        # we use the argv[1] as the input.
        self.initial_state = self.project.factory.entry_state(args=[self.exe, self.arg1])

        # make sure that we try a maximum of input_len chars
        #self.initial_state.add_constraints(self.arg1a[self.input_len] == 0)
        self.my_constraints = (self.arg1a[self.input_len] == 0)
        # and we have sufficient constraints for minimal length
        for i in range(self.input_len):
            self.initial_state.add_constraints(self.arg1a[i] != 0)

        EOF = lambda _min, _max: _min == _max and _max == 0
        for i, (_min, _max) in enumerate(constraint_range):
            assert not EOF(_min, _max)
            char = self.arg1a[i]
            if _min > 0:   self.initial_state.add_constraints(char >= _min)
            if _max < 255: self.initial_state.add_constraints(char <= _max)

        for pos in refused_range:
            arr = refused_range[pos]
            char = self.arg1a[pos]
            for (_min, _max) in arr:
                remove = self.initial_state.solver.Or(char < _min, char > _max)
                self.initial_state.add_constraints(remove)

    def update_args(self, input_len, prefix):
        """
        Various mappings to argument chars for easy access.
        Note that claripy.BVS('sym_arg', 8 * N) is equivalent
        to reduce(lambda x,y: x.concat(y), self.arg1a), but it
        gives us better access to individual elements
        """
        largs = range(0, input_len+1)
        arg1k = ['%s_%d' % (prefix, i) for i in largs]
        self.arg1k8 = {i:'%s_%d_%d_8' % (prefix, i,i) for i in largs}
        self.arg1h = {k:claripy.BVS(k, 8, explicit_name=k) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        return reduce(lambda x,y: x.concat(y), self.arg1a)

    def stack_depth(self, state):
        stk, i = state.callstack, 0
        while stk: stk, i = stk.next, i+1
        return i

    def mmx(self, state, char):
        return (state.solver.min(char), state.solver.max(char))

    def range_at(self, state, at):
        c = self.arg1a[at]
        return self.mmx(state, c)

    def is_it(self, sg, stack_depth):
        if self.is_successful(sg.state):
            print "XXXXXXXXXXXXXXXXXXXXXXXXXXX"
            return True
        if self.stack_depth(sg.state) < stack_depth:
            return True
        else:
            return False

    def choose_a_successor_state(self, pstate, states):
        """
        Which successor state to expand? We may apply various heuristics here
        First, we sort by the smallest strings (zero starting). Then choose
        the smallest string(s)
        -- another is to look for the stack depth. If we are above the threshold
        (say 80% of Max_Input_Len), and we wish to start closing, then
        we might choose the successor state that has the least self.stack_depth
        On the other hand, it may be that closing requires additional procedures
        in which case this heuristic might fail
        -- Similarly, another alternative is to look at the constraints added on
        the last character on each state. If the constraint on a state is
        similar enough to the constraints on last_character - 1, then choose
        the other.

        Finally, we need to find a way to ignore the spurious constraints -- i.e
        the constraints generated by strlen.
        """
        assert states

        if True: #self.input_len == 0:
            # first state. We dont have previous values to look back to
            i = random.randint(0, len(states)-1)
            state = states.pop(i)
            return state, states

        last = self.input_len - 1
        (m, n) = self.range_at(pstate, last)
        ss = list(enumerate(states))
        si = [i for i,s in ss]

        # TODO: Explore the next n successors, and find if any of these have
        # smaller stack depth.

        # sd = self.stack_depth(pstate)
        # shallow_state_idx = []
        # for i, s in ss:
        #     simgr = self.project.factory.simulation_manager(s)
        #     sm = simgr.explore(find=lambda sg: self.is_it(sg, sd))
        #     for s in sm.found: shallow_state_idx.append(i)
        # si = shallow_state_idx if shallow_state_idx else si

        ss = [(self.stack_depth(s[_child]), i) for i, s in ss]
        dmin = min(d for d,i in ss)
        dmax = min(d for d,i in ss)
        print (dmin, dmax)
        si = [i for d,i in ss if d == dmin]

        # now, select all that is different from original constraints
        si_ = [i for i in si if self.range_at(states[i][_child], last+1) != (m, n)]
        if si_: si = si_

        rand_i = random.choice(si)
        state = states.pop(rand_i)
        return state, states

    def choose_a_previous_path(self, states):
        """
        Choises: Choose the last state, choose a random state, use a heuristic
        Heuristic: Rather than go for random state, or the last
        state, choose the last states with more probability than the first
        ones.
        """
        assert states
        arr, sl = [], len(states)
        for i in range(sl): arr.extend([i]*(1 + i*Prob_Mul_Factor))
        si = arr[random.randint(0, len(arr)-1)]
        state = states.pop(si)
        return state, states

    def get_char_range(self, state):
        return [self.mmx(state, c) for c in self.arg1a]

    def next_step(self, state):
        while True:
            try:
                succ = state.step(extra_constraints=self.my_constraints)
                if len(succ.flat_successors) != 1: return state, succ
                state = succ.flat_successors[0]
            except angr.errors.SimUnsatError, ue:
                embed(globals(), locals())

    def gen_chains(self, state):
        states = []
        while True:
            if self.is_successful(state): return (R.SUCCESS,state)
            pstate, succ = self.next_step(state)
            my_succ =  [(pstate, s) for s in succ.flat_successors]
            nsucc = len(my_succ)
            if nsucc == 0:
                if not states: return (R.NO_STATES, state)
                (pstate, state), states = self.choose_a_previous_path(states)
            else:
                assert nsucc > 1
                (pstate, state), ss = self.choose_a_successor_state(pstate, my_succ)
                states.extend(ss)

            val = constraint_to_chr(self.get_char_range(state))
            print "> %s" % repr(val)
            # was there a change in constraints?
            parent_ranges = self.get_char_range(pstate)
            current_ranges = self.get_char_range(state)

            updated_idx = -1
            for i, (p, c) in enumerate(zip(parent_ranges, current_ranges)):
                if p != c:
                    assert p[_min] <= c[_min] and p[_max] >= c[_max]
                    updated_idx = i
                    # commit here
                    states = []
                    # char = chr(random.randint(c[_min], c[_max]))
                    if c[_min] != c[_max]:
                        log("@%d [%s-%s]" % (updated_idx, chr(c[_min]), chr(c[_max])))
                    else:
                        log("@%d [%s]" % (updated_idx, chr(c[_min])))
                    break

def constraint_to_chr(r, interpret=False):
    arr = []
    for (min_,max_) in r:
        if interpret:
            #v = chr(random.randint(min_, max_)) if min_ != max_ else chr(min_)
            v = chr(min_)
        else:
            v = '[%s-%s]' % (chr(min_), chr(max_)) if min_ != max_ else chr(min_)
        arr.append(v)
    return "".join(arr)

import pudb; 
import bdb; 
def update_constraints(constraint_range, pos, refuse_range):
    v = constraint_range.pop()
    assert v == (1, 255)
    last = constraint_range.pop()
    # take the range that is between min
    if pos not in refuse_range: refuse_range[pos] = []
    refuse_range[pos].append(last)
    return constraint_range

def main(exe, out):
    status, state = None, None
    constraint_range = []
    checked_constraints = {}
    prog = Program(exe)

    my_iter = iter(range(Max_Input_Len))
    inp_len = next(my_iter)
    while True:
        log("input_len: %d" % inp_len)
        print "Applying constraint:<%s>" % constraint_to_chr(constraint_range)
        prog.update(inp_len, constraint_range, checked_constraints)
        status, state = prog.gen_chains(prog.initial_state)
        print status
        if status == R.SUCCESS:
            val = constraint_to_chr(prog.get_char_range(state), True)
            print "SUCCESS: %s" % repr(val)
            print >>out, "<%s>" % repr(val)
            out.flush()
            constraint_range = []
        elif status == R.NO_STATES:
            # all except the last zero termination.
            constraint_range = prog.get_char_range(state)[0:-1]
            print "NOSTATES: %s" % repr(constraint_to_chr(constraint_range, True))
            # check the last but one state. If it is not changed, it is time
            # to update constraint.
            if constraint_range:
                if constraint_range[inp_len-1] == (1, 255): # -1
                    # first strip out the last
                    constraint_range = update_constraints(constraint_range,
                            inp_len-2, checked_constraints)
                    continue

        else:
            print "OTHER"
        inp_len = next(my_iter)
try:
    with open("results.txt", "w+") as f: main(sys.argv[1], f)
except (KeyboardInterrupt, SystemExit, bdb.BdbQuit, StopIteration):
    sys.exit(0)
