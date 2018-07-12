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
GC = False
Closing_Threshold = 0.8
Closing_Strip = True
Closing_Buffer = 1000
Max_Input_Len = int(os.environ.get('MAX_INPUT', '100'))
Min_Input_Len = int(os.environ.get('MIN_INPUT', '0'))
Success_Fn = os.environ.get('SUCCESS_FN', 'success')
Random_Seed = int(os.environ.get('R', '0'))
random.seed(Random_Seed)
_min, _max = 0, 1

Count_Down = range(Max_Input_Len-1, -1, -1)
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
    def __init__(self, exe, input_len, constraint_range, refused_range):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        self.success_fn = self.get_fn_addr(Success_Fn)

        self.input_len = input_len
        # generate arg1 from individual characters.
        self.arg1 = self.update_args(self.input_len, prefix='sym_arg')

        # we use the argv[1] as the input.
        self.initial_state = self.project.factory.entry_state(args=[exe, self.arg1])

        # make sure that we try a maximum of input_len chars
        self.initial_state.add_constraints(self.arg1a[self.input_len] == 0)
        # and we have sufficient constraints for minimal length
        for i in range(self.input_len):
            self.initial_state.add_constraints(self.arg1a[i] != 0)

        for i, (_min, _max) in enumerate(constraint_range):
            assert not (_min == _max and _max == 0)
            if _min > 0:
                self.initial_state.add_constraints(self.arg1a[i] >= _min)
            if _max < 255:
                self.initial_state.add_constraints(self.arg1a[i] <= _max)

        for pos in refused_range:
            arr = refused_range[pos]
            for (_min, _max) in arr:
                self.initial_state.add_constraints(self.initial_state.solver.Or(self.arg1a[pos] < _min,self.arg1a[pos] > _max))

    def is_successful(self, state):
        return self.success_fn == state.addr

    def update_constraint_rep(self, state):
        """
        Used to check if a constraint has been updated
        """
        self.last_constraints = [claripy.simplify(c) for c in state.solver.constraints]

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

    def update_checked_idx(self):
        """
        Update the last character that has been resolved (i.e. made printable)
        """
        # why can't we just use self.state.solver.solution(self.arg1a[i],0)?
        # The problem is that many string manipulation routines check for
        # the existance of null terminator by looking for arg[i] == 0
        # Since we are in symbolic land, quite often we may be in situations
        # where the execution may have gone overboard in doing the strlen
        # and assumed most intervening characters to be > 0 Hence, we
        # might find quite a lot of \x001 which are not actually genuine
        # character constraints. Hence we explicitly look for printable

        # First generate the set of character constraints.
        db = set(reduce(lambda x, y: x.union(y),
                         self.retrieve_vars_in_constraints(self.state)))
        self.last_char_checked = 0
        for i in Count_Down:
            # If no constraints exist for this character, then this character
            # has not been resolved yet.
            if self.arg1k8[i] not in db: continue
            # if the current character checked is not printable, then
            # it stands to reason that it was not fully resolved. In which
            # case, continue to the next loop.
            if not self.is_printable(self.arg1a[i]): continue
            # this is the first character to have been resolved fully.
            self.last_char_checked = i
            return i

    def retrieve_vars_in_constraints(self, state):
        return [state.solver.variables(c) for c in state.solver.constraints]

    def is_printable(self, char):
        m, n = self.state.solver.min(char), self.state.solver.max(char)
        return m > 31 and n < 128

    def make_printable(self, char):
        self.initial_state.add_constraints(char < 128)
        self.initial_state.add_constraints(char > 31)

    def get_fn_addr(self, fname):
        if 'cfg' not in self.__dict__:
            self.cfg = self.project.analyses.CFG(fail_fast=True)
        functions = self.cfg.kb.functions
        found = [addr for addr,f in functions.iteritems() if fname == f.name]
        assert len(found) == 1, "No address found for function : %s" % fname
        return found[0]

    def begin_closing(self):
        return self.last_char_checked > (Closing_Threshold * Max_Input_Len)

    def str_len(self, state):
        """
        Return the zero termination of the argument string
        """
        ret = 0
        for i in Count_Down:
            # we count from the back. So if any character
            # does not have zero as a solution, then its
            # next character is the zero termination
            if not state.solver.max(self.arg1a[i], 0):
                ret = i + 1
                break
        return ret

    def mmx(self, state, char):
        return (state.solver.min(char), state.solver.max(char))

    def range_at(self, state, at):
        c = self.arg1a[at]
        return self.mmx (state, c)

    def choose_a_successor_state(self, states):
        i = random.randint(0, len(states)-1)
        state = states.pop(i)
        return state, states
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
        self.update_checked_idx()
        last = self.last_char_checked
        (m, n) = self.range_at(self.state, last)
        ss = list(enumerate(states))
        si = [i for i,s in ss]

        # TODO: Explore the next n successors, and find if any of these have
        # smaller stack depth.
        if self.begin_closing():
            # begin closing -- stack depth gets priority
            ss = [(self.stack_depth(s), i) for i, s in ss]
            di = min(d for d,i in ss)
            si = [i for d,i in ss if d == di]

            # now, get the smallest string length
            ss = [(self.str_len(states[i]), i) for i in si]
            zi = min(z for z, i in ss)
            si = [i for z,i in ss if z == zi]

            # now, select all that is different from original constraints
            si_ = [i for i in si if self.range_at(states[i], last+1) != (m, n)]
            if si_: si = si_

        else:
            # not closing. The constraints get priority
            si = [i for i,s in ss]
            si_ = [i for i in si if self.range_at(states[i], last+1) != (m, n)]
            if si_: si = si_

            # then go for the smallest strings
            ss = [(self.str_len(states[i]), i) for i in si]
            zi = min(z for z,i in ss)
            si = [i for z,i in ss if z == zi]
            # we dont care for stack depth at this point.

        rand_i = random.choice(si)
        state = states.pop(rand_i)
        return state, states

    def choose_a_previous_path(self, states):
        i = random.randint(0, len(states)-1)
        state = states.pop(i)
        return state, states
        """
        Choises: Choose the last state, choose a random state, use a heuristic
        Heuristic: Rather than go for random state, or the last
        state, choose the last states with more probability than the first
        ones.
        """
        assert states
        sl = len(states)
        arr = []
        for i in range(sl): arr.extend([i]*(1 + i*Prob_Mul_Factor))
        si = arr[random.randint(0, len(arr)-1)]
        state = states[si]
        states.pop(si)
        return state, states

    def print_constraints(self):
        for i,c in enumerate(self.state.solver.constraints):
            v = list(self.state.solver.variables(c))
            log("\t? %d: %s === %s" % (i, c, str(v)))

    def identical_constraints(self, xs, ys):
        xsc = claripy.And(*xs)
        ysc = claripy.And(*ys)
        return claripy.backends.z3.identical(xsc, ysc)

    def gc(self, states):
        if not GC: return states
        if not Closing_Strip: return states
        if len(states) > Closing_Buffer:
            print "start stripping from:", len(states)
            # strip out all but best 100
            ss = sorted([(self.stack_depth(s), i) for i, s in enumerate(states)])
            ss = ss[0:Closing_Buffer]
            states = [states[i] for d, i in ss]
            return states
        return states

    def get_char_range(self, state):
        return [self.mmx(state, c) for c in self.arg1a]

    def gen_chains(self, state):
        states = []
        while True:
            if self.is_successful(state): return (R.SUCCESS,state)
            try:
                succ = state.step() # try
                my_succ =  [(state, s) for s in succ.flat_successors]
                nsucc = len(my_succ)
                if nsucc == 1:
                    (pstate, state) = my_succ.pop()
                    continue
                if nsucc == 0:
                    # No active successors.
                    if not states:
                        return (R.NO_STATES, state)
                    (pstate, state), states = self.choose_a_previous_path(states)
                elif nsucc > 1:
                    (pstate, state), ss = self.choose_a_successor_state(my_succ)
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

            except angr.errors.SimUnsatError, ue:
                embed(globals(), locals())

    def cstr(self, val):
        for i in range(len(val)):
            if val[i] == '\x00':
                return val[0:i]
        return val

    def get_args(self, state):
        val = state.solver.eval(self.arg1, cast_to=str)
        for i in range(len(val)):
            if val[i] == '\x00':
                return val[0:i]
        return val

    def print_args(self, state, il):
        for i in state.solver.eval_upto(self.arg1, 1, cast_to=str):
            log(repr(i)) #.strip('\x00\xff')))

def constraint_to_chr(r):
    arr = []
    for (min_,max_) in r:
        if min_ == max_:
            arr.append(chr(min_))
        else:
            # c = chr(random.randint(a, b))
            c = chr(min_)
            arr.append(c)
    return "".join(arr)

import pudb; 
import bdb; 
def update_constraints(constraint_range, pos, refuse_range):
    #pudb.set_trace()
    v = constraint_range.pop()
    assert v == (1, 255)
    last = constraint_range.pop()
    # take the range that is between min
    if pos not in refuse_range: refuse_range[pos] = []
    refuse_range[pos].append(last)
    return constraint_range

def main(exe):
    status, state = None, None
    constraint_range = []
    checked_constraints = {}
    with open("results.txt", "w+") as f:
        my_iter = iter(range(Max_Input_Len))
        inp_len = next(my_iter)
        while True:
            # pudb.set_trace(inp_len == 9)
            log("input_len: %d" % inp_len)
            print "Applying constraint:<%s>" % constraint_to_chr(constraint_range)
            prog = Program(exe, inp_len, constraint_range, checked_constraints)
            status, state = prog.gen_chains(prog.initial_state)
            print status
            if status == R.SUCCESS:
                val = constraint_to_chr(prog.get_char_range(state))
                print "SUCCESS: %s" % repr(val)
                print >>f, "<%s>" % repr(val)
                f.flush()
                constraint_range = []
            elif status == R.NO_STATES:
                # all except the last zero termination.
                constraint_range = prog.get_char_range(state)[0:-1]
                print "NOSTATES: %s" % repr(constraint_to_chr(constraint_range))
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
    main(sys.argv[1])
except (KeyboardInterrupt, SystemExit, bdb.BdbQuit):
    sys.exit(0)
