#!/usr/bin/env python

import sys
import os
import time
import angr
import random
import claripy

# How to choose the next state. The Prob_Mul_Factor skews the
# probability distribution of choise of elements from the list
# of states. If greater than 0, it gives a slightly higher
# weightage to the later states. If it is 0, it is same as
# random sampling.
Prob_Mul_Factor = 0

# Count_Down because there may be no constraints at the tail
Count_Down = True
Closing_Threshold = 0.8
Closing_Strip = True
Closing_Buffer = 1000
Max_Input_Len = int(os.environ.get('MAX_INPUT', '10'))
Min_Input_Len = int(os.environ.get('MIN_INPUT', '0'))
Success_Fn = os.environ.get('SUCCESS_FN', 'success')
Random_Seed = int(os.environ.get('R', '0'))
Prefer_Shortest_Strings = True
random.seed(Random_Seed)

# Given a range of solutions, should we fix one solution
# before we explore further?
Quick_Fix = True

def w(v):
    sys.stderr.write(v)
    sys.stderr.flush()

def log(v): w("\t%s\n" % v)

class Program:
    def __init__(self, exe):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        self.update_args()
        self.initial_state = self.project.factory.entry_state(args=[exe, self.arg1])

        # make sure that we try a maximum of Max_Input_Len chars
        self.initial_state.add_constraints(self.arg1a[Max_Input_Len] == 0)
        for i in range(Min_Input_Len):
            self.initial_state.add_constraints(self.arg1a[i] != 0)

        self.cfg = self.project.analyses.CFG(fail_fast=True)
        self.success_fn = self.get_fn_addr(Success_Fn)

        self.state = self.initial_state
        self.update_constraint_rep(self.state)

        self.states = []
        self.extra_states = []

        self.last_char_checked = 0
        self.update_checked_char()

    def update_constraint_rep(self, state):
        """
        The string representation of all constraints. Used to check if a
        constraint has been updated
        """
        self.last_constraints = [claripy.simplify(c) for c in state.solver.constraints]

    def update_args(self):
        """
        Various mappings to argument chars for easy access.
        Note that claripy.BVS('sym_arg', 8 * N) is equivalent
        to reduce(lambda x,y: x.concat(y), self.arg1a), but it
        gives us better access to individual elements
        """
        arg1k = ['sym_arg_%d' % i for i in range(0, Max_Input_Len+1)]
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        self.arg1 = reduce(lambda x,y: x.concat(y), self.arg1a)

    def stack_depth(self, state):
        stk = state.callstack
        i = 0
        while stk:
            stk = stk.next
            i += 1
        return i

    def update_checked_char(self):
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

        if Count_Down:
            db = set(reduce(lambda x, y: x.union(y), self.retrieve_char_constraints(self.state)))
            self.last_char_checked = 0
            for i in range(Max_Input_Len-1, -1, -1):
                if ("sym_arg_%d_%d_8" % (i, i)) not in db: continue
                if self.is_printable(self.arg1a[i]):
                    self.last_char_checked = i
                    break
        else:
            for i in range(self.last_char_checked+1, Max_Input_Len):
                if not self.is_printable(self.arg1a[i]): break
                self.last_char_checked = i

    def retrieve_char_constraints(self, state):
        return [state.solver.variables(c) for c in state.solver.constraints]

    def is_printable(self, char):
        m, n = self.state.solver.min(char), self.state.solver.max(char)
        return m > 31 and n < 128

    def make_printable(self, char):
        self.initial_state.add_constraints(char < 128)
        self.initial_state.add_constraints(char > 31)

    def get_fn_addr(self, fname):
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
        if Count_Down:
            ret = 0
            for i in range(Max_Input_Len-1, -1, -1):
                # we count from the back. So if any character
                # does not have zero as a solution, then its
                # next character is the zero termination
                if not state.solver.solution(self.arg1a[i], 0):
                    ret = i + 1
                    break
            return ret
        else:
            for i in range(0, Max_Input_Len):
                m = state.solver.min(self.arg1a[i])
                if m == 0:
                    return i
            return Max_Input_Len

    def range_at(self, state, at):
        c = self.arg1a[at]
        return (state.solver.min(c), state.solver.max(c))

    def choose_a_successor_state(self, states):
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
        self.update_checked_char()
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
        i = random.randint(0, len(arr)-1)
        si = arr[i]
        state = states[si]
        states.pop(si)
        return state, states

        # i = random.randint(0, len(states)-1)
        # state = states.pop(i)
        # return state, states

        # state = states.pop()

    def print_constraints(self):
        for i,c in enumerate(self.state.solver.constraints):
            v = list(self.state.solver.variables(c))
            log("\t? %d: %s === %s" % (i, c, str(v)))

    def identical_constraints(self, xs, ys):
        xsc = claripy.And(*xs)
        ysc = claripy.And(*ys)
        return claripy.backends.z3.identical(xsc, ysc)

    def gen_chains(self, state=None):
        states = self.states if self.states else []
        if not state: state = self.state
        while True:
            if Closing_Strip:
                if len(self.states) > Closing_Buffer:
                    print "start stripping from:", len(self.states)
                    # strip out all but best 100
                    ss = sorted([(self.stack_depth(s), i) for i, s in enumerate(self.states)])
                    ss = ss[0:Closing_Buffer]
                    states = [self.states[i] for d, i in ss]
                    self.states = states
            try:
                if state.addr == self.success_fn: return ('success',state)
                w("<")
                w("%d+" % len(states))
                my_succ = state.step().flat_successors # succ.successors for symbolic
                nsucc = len(my_succ)
                w(str(nsucc))
                w(">")
                # time.sleep(1)
                if nsucc == 0:
                    # No active successors. This can be due to our Max_Input_Len
                    # overshooting.
                    log("<< %d" % len(states))
                    w("(")
                    self.last_char_checked = 0
                    w(".")
                    if not states: return ('no_states', None)
                    w(".")
                    state, states = self.choose_a_previous_path(states)
                    self.update_checked_char()
                    w(")")
                    self.state = state
                    self.states = states
                elif nsucc > 1:
                    w("{")
                    arg = self.get_args(state)
                    w(repr(arg))
                    w(",")
                    state, ss = self.choose_a_successor_state(my_succ)
                    self.update_checked_char()
                    arg = self.get_args(state)
                    w(repr(arg))
                    w("}")
                    states.extend(ss)
                    self.states = states
                    self.state = state
                else:
                    w(".")
                    state = my_succ[0]
                    continue

                # were there any new chars?
                w("[")
                current_constraints = [claripy.simplify(c) for c in state.solver.constraints]
                if not self.identical_constraints(current_constraints, self.last_constraints):
                    self.last_constraints = current_constraints
                    # were there any constraints?
                    if  self.is_printable(self.arg1a[self.last_char_checked+1]):
                        # log("adding: %s at %d" % (chr(m), self.last_char_checked))
                        # now concretize
                        # TODO: save the state with opposite constraints after
                        # checking unsat
                        val = state.solver.eval(self.arg1a[self.last_char_checked])
                        w("@%d: %s" % (self.last_char_checked, chr(val)))

                        # check if an equality operator is involved
                        c = self.arg1a[self.last_char_checked]
                        if Quick_Fix and state.solver.max(c) != state.solver.min(c):
                            not_state = state.copy()
                            not_state.add_constraints(c != val)
                            self.extra_states.append(not_state)
                            state.add_constraints(c == val)
                        self.update_constraint_rep(state)
                        log("]")
                    else:
                        # the constraint added was not one on the input character
                        # hence we ignore.
                        w("x]")
            except angr.errors.SimUnsatError, ue:
                log('unsat.. %s' % str(ue))
                if not states: return ('no_states', None)
                state, states = self.choose_a_previous_path(states)

    def get_constraint_db(self):
        constraint_db = {}
        for vi in self.retrieve_char_constraints(self.state):
            # there could be multiple variables in a constraint
            # vi is a set of variables.
            for i in vi:
                if i in self.arg1h_:
                    v = self.arg1h_[i]
                    if v not in constraint_db: constraint_db[v] = 0
                    constraint_db[v] += 1
                else:
                    pass
                    #log("? %s" % i)
        return constraint_db

    def get_args(self, state):
        #return state.solver.eval(self.arg1, cast_to=str)[0:self.last_char_checked+1]
        val = state.solver.eval(self.arg1, cast_to=str)
        for i in range(len(val)):
            if val[i] == '\x00':
                return val[0:i]
        return val

    def print_args(self, state):
        for i in state.solver.eval_upto(self.arg1, 1, cast_to=str):
            log(repr(i[0:self.last_char_checked+1])) #.strip('\x00\xff')))

Show_Range = False
def main(exe):
    prog = Program(exe)
    status, state = None, None
    with open("results.txt", "w+") as f:
        while True:
            status, state = prog.gen_chains()
            print status
            prog.print_args(state)
            if status == 'success':
                prog.update_checked_char()
                print >>f, "<%s>" % repr(prog.get_args(state))
                if Show_Range:
                    minval = []
                    maxval = []
                    for i in range(prog.last_char_checked+1):
                        c = prog.arg1a[i]
                        x, y = state.solver.min(c), state.solver.max(c)
                        minval.append(chr(x))
                        maxval.append(chr(y))
                    print >>f, "min:", repr("".join(minval))
                    print >>f, "max:", repr("".join(maxval))
                # print >>f, "\t (%s)" % repr(i[0:prog.last_char_checked+1])
                f.flush()
            log("remaining: %d" % len(prog.states))
            if not prog.states:
                print "No more states extra_states:", len(prog.extra_states)
                break
            prog.state = prog.states.pop()

main(sys.argv[1])

# state = prog.gen_chains()
# print("----------------")
# cdb = prog.get_constraint_db()
# for i in cdb: print i, cdb[i]

