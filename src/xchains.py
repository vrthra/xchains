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
Success_Fn = os.environ.get('SUCCESS_FN', 'my_success')
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

class I(Enum):
    RANDOM = 0
    MIN = 1
    RANGE = 1

def w(v):
    sys.stderr.write(v)
    sys.stderr.flush()

def log(v): w("\t%s\n" % v)

def mmx(state, char):
    return (state.solver.min(char), state.solver.max(char))


def constraint_to_chr(my_ranges, interpret=I.RANGE):
    def to_char(min_, max_, i):
        if i == I.MIN:
            v = chr(min_)
        elif i == I.RANDOM:
            v = chr(random.randint(min_, max_))
        elif i == I.RANGE:
            v = '[%s-%s]' % (chr(min_), chr(max_)) if min_ != max_ else chr(min_)
        else: assert False
        return v
    arr = [to_char(min_,max_,interpret) for (min_,max_) in my_ranges]
    return "".join(arr)

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

    def stack_trace(self, state):
        stk = state.callstack
        while stk:
            if stk.func_addr in self.cfg.kb.functions:
                print "|\t", self.cfg.kb.functions[stk.func_addr].name
            stk = stk.next

    def is_successful(self, state): return self.success_fn == state.addr

    def update(self, input_len, constraint_range, refused_range):
        self.input_len = input_len
        # generate arg1 from individual characters.
        self.arg1 = self.update_args(self.input_len, prefix='sym_arg')

        # we use the argv[1] as the input.
        self.initial_state = self.project.factory.entry_state(args=[self.exe, self.arg1])

        # make sure that we try a maximum of input_len chars
        self.initial_state.add_constraints(self.arg1a[self.input_len] == 0)
        self.eof = (self.arg1a[self.input_len] == 0)
        # and we have sufficient constraints for minimal length
        for i in range(self.input_len):
            self.initial_state.add_constraints(self.arg1a[i] != 0)

        for i, (_min, _max) in enumerate(constraint_range):
            assert not EOF((_min, _max))
            char = self.arg1a[i]
            if _min > 0:   self.initial_state.add_constraints(char >= _min)
            if _max < 255: self.initial_state.add_constraints(char <= _max)

        # These are characters that, _given all the other characters in front_
        # should not be used because they were refused previously.
        for pos in refused_range:
            if pos >= input_len: continue
            arr = refused_range[pos]
            char = self.arg1a[pos]
            for (_min, _max) in arr:
                remove = self.initial_state.solver.Or(char < _min, char > _max)
                self.initial_state.add_constraints(remove)

        self.simgr = self.project.factory.simulation_manager(self.initial_state)
        old_state = None
        # now step until we come to the forking state.
        while len(self.simgr.active) == 1:
            old_state = self.simgr.active[0]
            self.simgr.step()
        return old_state


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

    def range_at(self, state, at):
        c = self.arg1a[at]
        return mmx(state, c)

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
        def overlap(r1, r2):
            if r1[_min] >= r2[_min] and r1[_max] <= r2[_max]:
                return True
            if r2[_min] >= r1[_min] and r2[_max] <= r1[_max]:
                return True
            return False

        if self.input_len == 0:
            # first state. We dont have previous values to look back to
            i = random.randint(0, len(states)-1)
            state = states.pop(i)
            return (pstate, state), [(pstate, s) for s in states]

        last = self.input_len - 1
        (m, n) = self.range_at(pstate, last)
        ss = [(self.stack_depth(s), i) for i, s in list(enumerate(states))]
        dmin = min(d for d,i in ss)
        si = [i for d,i in ss if d == dmin]

        # now, select all that is different from original constraints
        si_ = [i for i in si if not overlap(self.range_at(states[i], last+1), (m, n))]
        if si_: si = si_

        rand_i = random.choice(si)
        state = states.pop(rand_i)
        return (pstate, state), [(pstate, s) for s in states]

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
        return [mmx(state, c) for c in self.arg1a]

    def next_step(self, state):
        while True:
            try:
                # succ = state.step(extra_constraints=self.eof).flat_successors
                succ = state.step().flat_successors
                l = len(succ)
                succ = [s for s in succ if s.satisfiable(extra_constraints=[self.eof])]
                assert l == len(succ)
                if len(succ) != 1: return state, succ
                state = succ[0]
            except angr.errors.SimUnsatError, ue:
                embed(globals(), locals())

    def did_constraints_change(self, pstate, state):
        # was there a change in constraints?
        parent_ranges = self.get_char_range(pstate)
        current_ranges = self.get_char_range(state)

        pval = constraint_to_chr(parent_ranges, I.RANGE)
        val = constraint_to_chr(current_ranges, I.RANGE)
        print "> %s" % repr(val)

        for i, (p, c) in enumerate(zip(parent_ranges, current_ranges)):
            if i < self.input_len-1:
                #if p != c:
                #    embed(globals(), locals())
                pass
            else:
                if p != c:
                    assert p[_min] <= c[_min] and p[_max] >= c[_max]
                    #if it is printable,
                    # commit here
                    if c[_min] != c[_max]:
                        log("@%d [%s-%s]" % (i, repr(chr(c[_min])), repr(chr(c[_max]))))
                    else:
                        log("@%d [%s]" % (i, chr(c[_min])))
                    if printable(c): return True
                else:
                    pass
                    # log("drop [%s-%s]" % (repr(chr(c[_min])), repr(chr(c[_max]))))

    def gen_chains(self, state):
        states = []
        while True:
            if self.is_successful(state): return (R.SUCCESS,state)
            pstate, my_succ = self.next_step(state)
            if not my_succ:
                if not states: return (R.NO_STATES, state)
                (pstate, state), states = self.choose_a_previous_path(states)
            else:
                (pstate, state), ss = self.choose_a_successor_state(pstate, my_succ)
                states.extend(ss)
            if self.did_constraints_change(pstate, state):
                states = []

def unconstrained(v): return v[_min] == 0  and v[_max] == 255
def noz_unconstrained(v): return v[_min] == 1  and v[_max] == 255
def EOF(v): return v[_min] == v[_max] and v[_max] == 0
def printable(v): return v[_min] > 31 and v[_max] < 127
def constrained(v): return v[_min] > 1 or v[_max] < 255

import pudb; 
import bdb;

def undo_last_constraint(constraint_range, pos, refuse_range):
    # First strip out the last 
    v = constraint_range.pop()
    assert noz_unconstrained(v)

    # now, what was added
    last = constraint_range.pop()
    # take the range that is between min
    if pos not in refuse_range: refuse_range[pos] = []
    refuse_range[pos].append(last)
    return constraint_range

def find_return_fn(prog, state, st_size):
    sd = prog.stack_depth(state)
    if sd < st_size:
        return True
    return False

def main(exe, out):
    status, state = None, None
    constraint_range = []
    checked_constraints = {}
    prog = Program(exe)

    inp_len = 0
    while inp_len < Max_Input_Len:
        print("INPUT_LEN: %d" % inp_len)
        print "Applying constraint:<%s>" % constraint_to_chr(constraint_range, I.RANGE)
        old_state = prog.update(inp_len, constraint_range, checked_constraints)
        sdepth = prog.stack_depth(old_state)
        prog.stack_trace(old_state)

        if sdepth > 10:
            prog.simgr.explore(find=lambda st: find_return_fn(prog, st, sdepth))
            old_state = prog.simgr.found[0]
        status, state = prog.gen_chains(old_state)
        if status == R.SUCCESS:
            val = constraint_to_chr(prog.get_char_range(state), I.MIN)
            print "SUCCESS: %s" % repr(val)
            print >>out, "<%s>" % repr(val)
            out.flush()
            return
        elif status == R.NO_STATES:
            assert state != prog.success_fn
            prog.simgr = prog.project.factory.simulation_manager(state)
            v = prog.simgr.explore(find=lambda st: st.addr == prog.success_fn, n=1000)
            if v.found:
                print "==============="
                for s in v.found:
                    prog.stack_trace(s)
                    print "FOUND: %s" % repr(constraint_to_chr(prog.get_char_range(s), I.MIN))
                return
            # all except the last zero termination.
            # Note that since we are passing zero termination condition
            # separately, the prog.arg1a[-1] will be 0,0.
            # hence, we need to strip it out.
            constraint_range = prog.get_char_range(state)
            assert EOF(constraint_range[inp_len])
            eofelt = constraint_range.pop()
            assert EOF(eofelt)
            last_char = inp_len - 1
            print "NOSTATES: %s" % repr(constraint_to_chr(constraint_range, I.MIN))

            # sometimes, the current iteration may have gone down the wrong
            # path. When that happens, the next iteration will not add any
            # constraint onther than (min == 1).
            # IF that happens, We need to undo that character, save it
            # so that we wont try it again, and try next.
            if constraint_range and noz_unconstrained(constraint_range[last_char]):
                print "BACKUP-----------------------------------------"
                constraint_range = undo_last_constraint(constraint_range, inp_len-2, checked_constraints)
                inp_len -= 1
                continue

        else:
            assert False
        inp_len += 1
try:
    with open("results.txt", "w+") as f: main(sys.argv[1], f)
except (KeyboardInterrupt, SystemExit, bdb.BdbQuit, StopIteration):
    sys.exit(0)
