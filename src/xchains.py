#!/usr/bin/env python

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
Closing_Threshold = 0.8
Closing_Strip = True
Closing_Buffer = 1000
Max_Input_Len = int(os.environ.get('MAX_INPUT', '10'))
Min_Input_Len = int(os.environ.get('MIN_INPUT', '0'))
Success_Fn = os.environ.get('SUCCESS_FN', 'success')
Random_Seed = int(os.environ.get('R', '0'))
random.seed(Random_Seed)

Count_Down = range(Max_Input_Len-1, -1, -1)
# Given a range of solutions, should we fix one solution
# before we explore further?
Quick_Fix = True

def w(v):
    sys.stderr.write(v)
    sys.stderr.flush()

def log(v): w("\t%s\n" % v)

def pop_last(arr):
    i = arr.pop()
    return i, arr

def pop_random(arr):
    i = arr.pop(random.randint(0, len(arr)-1))
    return i, arr

class Program:

    def pop_smallest(self, arr):
        res = sorted([(self.str_len(a[1]), i) for i,a in enumerate(arr)])
        idx = res[0][1]
        i = arr.pop(idx)
        return i, arr
        

    def __init__(self, exe):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        self.success_fn = self.get_fn_addr(Success_Fn)

        # generate arg1 from individual characters.
        self.arg1 = self.update_args(Max_Input_Len, prefix='sym_arg')

        # we use the argv[1] as the input.
        self.initial_state = self.project.factory.entry_state(args=[exe, self.arg1])

        # make sure that we try a maximum of Max_Input_Len chars
        self.initial_state.add_constraints(self.arg1a[Max_Input_Len] == 0)
        # and we have sufficient constraints for minimal length
        for i in range(Min_Input_Len):
            self.initial_state.add_constraints(self.arg1a[i] != 0)

        self.state_constraints = {}

        self.last_char_checked = self.last_checked_idx(self.initial_state)

        self.extra_states = []

    def is_successful(self, state):
        return self.success_fn == state.addr

    def get_constraint_range(self, state):
        # Remember that str(state) is not a unique representation of
        # state. A better cache key may be
        # str(state.solver.constraints.simplify)
        return [(state.solver.min(c), state.solver.max(c)) for c in self.arg1a]

    def update_args(self, input_len, prefix):
        """
        Various mappings to argument chars for easy access.
        Note that claripy.BVS('sym_arg', 8 * N) is equivalent
        to reduce(lambda x,y: x.concat(y), self.arg1a), but it
        gives us better access to individual elements
        """
        largs = range(0, input_len+1)
        arg1k = ['%s_%d' % (prefix, i) for i in largs]
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        return reduce(lambda x,y: x.concat(y), self.arg1a)

    def stack_depth(self, state):
        stk, i = state.callstack, 0
        while stk: stk, i = stk.next, i+1
        return i

    def last_checked_idx(self, state):
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
                         self.retrieve_vars_in_constraints(state)))
        for i in Count_Down:
            # if the current character checked is not printable, then
            # it stands to reason that it was not fully resolved. In which
            # case, continue to the next loop.
            if not self.is_printable(state, i): continue
            # this is the first character to have been resolved fully.
            return i

    def retrieve_vars_in_constraints(self, state):
        return [state.solver.variables(c) for c in state.solver.constraints]

    def is_printable(self, state, i):
        m, n = self.range_at(state, i)
        return m > 31 and n < 128

    def get_fn_addr(self, fname):
        if 'cfg' not in self.__dict__:
            self.cfg = self.project.analyses.CFG(fail_fast=True)
        functions = self.cfg.kb.functions
        found = [addr for addr,f in functions.iteritems() if fname == f.name]
        assert len(found) == 1, "No address found for function : %s" % fname
        return found[0]

    def str_len(self, state):
        """
        Return the zero termination of the argument string
        """
        ret = 0
        for i in range(Max_Input_Len+1):
            if state.solver.max(self.arg1a[i]) == 0: return i
        return ret

    def range_at(self, state, at):
        c = self.arg1a[at]
        return (state.solver.min(c), state.solver.max(c))

    def choose_a_successor_state(self, states):
        return pop_random(states)

    def choose_a_previous_path(self, states):
        state, states = self.pop_smallest(states)
        return state, states

    def constraint_delta(self, s1, s2):
        # s1 has wider constraints. i.e its min is smaller and max is larger
        # than s2
        _min = 0
        _max = 1
        c1 = self.get_constraint_range(s1)
        c2 = self.get_constraint_range(s2)
        console = False
        for i, x1 in enumerate(c1):
            x2 = c2[i] 
            if not (x1[_min] <= x2[_min], "@%d ! %s <= %s" % (i, str(x1[_min]), str(x2[_min]))):
                print 'min'
                console = True
            if not (x1[_max] >= x2[_max], "@%d ! %s >= %s" % (i, str(x1[_max]), str(x2[_max]))):
                print 'max'
                console = True
            if console:
                console = False
                print ""
                print "parent:", s1, ":", c1
                print "child:", s2, ":", c2
                print ""
                embed(globals(), locals())

        return None, None

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
        for i in state.solver.eval_upto(self.arg1, 1, cast_to=str):
            log(repr(i)) #.strip('\x00\xff')))

Show_Range = False
def main(exe):
    prog = Program(exe)
    status, state = None, None
    with open("results.txt", "w+") as f:
        state = prog.initial_state
        while True:
            status, state = prog.gen_chains(state)
            print status
            if status == 'success':
                prog.print_args(state)
                prog.last_char_checked = prog.last_checked_idx(state)
                print >>f, "<%s>" % repr(prog.get_args(state))
                if Show_Range:
                    minval = []
                    maxval = []
                    for i in range(prog.last_char_checked+1):
                        x, y = prog.range_at(state, i)
                        minval.append(chr(x))
                        maxval.append(chr(y))
                    print >>f, "min:", repr("".join(minval))
                    print >>f, "max:", repr("".join(maxval))
                f.flush()
                if prog.extra_states:
                   (pstate, state), prog.extra_states = prog.choose_a_previous_path(prog.extra_states)
                else:
                    break
            else:
                if prog.extra_states:
                   (pstate, state), prog.extra_states = prog.choose_a_previous_path(prog.extra_states)
                else:
                    break
main(sys.argv[1])
