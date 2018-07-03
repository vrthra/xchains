#!/usr/bin/env python

import sys
import os
import time
import angr
import random
import claripy
from ptpython.repl import embed


# How to choose the next state. The Prob_Mul_Factor skews the
# probabilit distribution of choise of elements from the list
# of states. If greater than 0, it gives a slightly higher
# weightage to the later states. If it is 0, it is same as
# random sampling.
Prob_Mul_Factor = 0
Closing_Threshold = 0.8
Max_Input_Len = int(os.environ.get('MAX_INPUT', '10'))
Success_Fn = os.environ.get('SUCCESS_FN', 'success')
Random_Seed = int(os.environ.get('R', '0'))
random.seed(Random_Seed)

def log(v): print >>sys.stderr, "\t", v
def configure(repl): repl.confirm_exit = False

class Program:
    def __init__(self, exe):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        self.update_args()
        self.initial_state = self.project.factory.entry_state(args=[exe, self.arg1])

        # make sure that we try a maximum of Max_Input_Len chars
        self.initial_state.add_constraints(self.arg1a[Max_Input_Len] == 0)

        self.cfg = self.project.analyses.CFG(fail_fast=True)
        self.success_fn = self.get_fn_addr(Success_Fn)

        self.state = self.initial_state
        self.update_constraint_rep(self.state)

        self.icdb = self.get_constraint_db(self.state)
        self.cdb = self.icdb
        self.states = []

        self.last_char_checked = 0
        self.update_checked_char()

    def update_constraint_rep(self, state):
        """
        The string representation of all constraints. Used to check if a
        constraint has been updated
        """
        self.last_constraints = [claripy.simplify(c) for c in state.solver.constraints]

    def update_args(self):
        """ Various mappings to argument chars for easy access. """
        arg1k = ['sym_arg_%s' % str(i) for i in range(0, Max_Input_Len+1)]
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        # self.arg1 = claripy.BVS('sym_arg', 8 * )
        self.arg1 = reduce(lambda x,y: x.concat(y), self.arg1a)

    def stack_depth(self, state):
        stk = state.callstack
        i = 0
        while stk:
            stk = stk.next
            i += 1
        return i

    def update_checked_char(self):
        log( "t last: %d" % self.last_char_checked)
        # assert self.state.solver.min(self.arg1a[0]) > 31
        for i in range(self.last_char_checked+1, Max_Input_Len):
            m = self.state.solver.min(self.arg1a[i])
            # why can't we just use self.state.solver.solution(self.arg1a[i],0)?
            # The problem is that many string manipulation routines check for
            # the existance of null terminator by looking for arg[i] == 0
            # Since we are in symbolic land, quite often we may be in situations
            # where the execution may have gone overboard in doing the strlen
            # and assumed most intervening characters to be > 0 Hence, we
            # might find quite a lot of \x001 which are not actually genuine
            # character constraints. Hence we explicitly look for printable
            if not self.is_printable(self.arg1a[i]): break
            self.last_char_checked = i
            # print ">>>  update self.last_char_checked @%d: %s" % (i, chr(m))

    def retrieve_char_constraints(self, state):
        return [state.solver.variables(c) for c in state.solver.constraints]

    def is_printable(self, char):
        m = self.state.solver.min(char)
        n = self.state.solver.max(char)
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

    def choose_a_successor_state(self, states):
        """
        Which successor state to expand? We may apply various heuristics here
        -- One is to look for the stack depth. If we are above the threshold
        (say 50% of Max_Input_Len), and we wish to start closing, then
        we might choose the successor state that has the least self.stack_depth
        On the other hand, it may be that closing requires additional procedures
        in which case this heuristic might fail
        -- Similarly, another alternative is to look at the constraints added on
        the last character on each state. If the constraint on a state is
        similar enough to the constraints on last_character - 1, then choose
        the other.
        """
        assert states
        s = {self.stack_depth(x) for x in states}
        if len(s) > 1 and self.begin_closing():
            sorted_states = sorted(states, lambda x, y: cmp(self.stack_depth(x), self.stack_depth(y)))
            state = sorted_states.pop()
            return state, sorted_states
        else:
            self.update_checked_char()
            last = self.last_char_checked
            (m, n) = (self.state.solver.min(self.arg1a[last]), self.state.solver.max(self.arg1a[last]))

            sel = []
            for i, s in enumerate(states):
                (m0, n0) = (s.solver.min(self.arg1a[last+1]), s.solver.max(self.arg1a[last+1]))
                if (m, n) != (m0, n0): sel.append(i)

            i = random.randint(0, len(states)-1)
            if sel: i = random.choice(sel)
            state = states.pop(i)
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
            try:
                if state.addr == self.success_fn: return ('success',state)
                my_succ = state.step().flat_successors # succ.successors for symbolic
                nsucc = len(my_succ)
                # time.sleep(1)
                if nsucc == 0:
                    # No active successors. This can be due to our Max_Input_Len
                    # overshooting.
                    log("__ %d" % len(states))
                    self.last_char_checked = 0
                    self.update_checked_char()
                    if not states: return ('no_states', None)
                    state, states = self.choose_a_previous_path(states)
                    self.state = state
                    self.states = states
                elif nsucc > 1:
                    self.print_args(state)
                    log("successors: %d" % nsucc)
                    state, ss = self.choose_a_successor_state(my_succ)
                    states.extend(ss)
                    self.states = states
                    self.state = state
                    # self.print_constraints()
                    log("============")
                else:
                    sys.stderr.write(".")
                    state = my_succ[0]
                    continue

                # were there any new chars?
                m = state.solver.min(self.arg1a[self.last_char_checked+1])
                current_constraints = [claripy.simplify(c) for c in state.solver.constraints]
                if not self.identical_constraints(current_constraints, self.last_constraints):
                    self.last_constraints = current_constraints
                    # were there any constraints?
                    log("new constraints")
                    if self.last_char_checked < Max_Input_Len - 1 and m > 31 and m < 128:
                        log("adding: %s at %d" % (chr(m), self.last_char_checked))
                        self.update_checked_char()

                        # now concretize
                        # TODO: save the state with opposite constraints after
                        # checking unsat
                        val = state.solver.eval(self.arg1a[self.last_char_checked])
                        log("-----> @%d: %s" % (self.last_char_checked, chr(val)))
                        # # not_state = state.copy()
                        # # not_state.add_constraints(self.arg1a[self.last_char_checked] != val)
                        # # not_state.simplify()
                        # # self.states.append(not_state)

                        # # state.add_constraints(self.arg1a[self.last_char_checked] == val)
                        self.update_constraint_rep(state)
                    else:
                        log("->ignored")
            except angr.errors.SimUnsatError, ue:
                log('unsat.. %s' % str(ue))
                if not states: return (None, None)
                state, states = self.choose_a_previous_path(states)

    def get_constraint_db(self, state):
        constraint_db = {}
        for vi in self.retrieve_char_constraints(state):
            # there could be multiple variables in a constraint
            # vi is a set of variables.
            for i in vi:
                if i in self.arg1h_:
                    v = self.arg1h_[i]
                    if v not in constraint_db: constraint_db[v] = 0
                    constraint_db[v] += 1
                else:
                    log("? %s" % i)
        return constraint_db

    def update_constraints(self):
        cdb_ = self.cdb
        self.cdb = self.get_constraint_db(self.state)
        for i in self.icdb:
            if self.cdb[i] > cdb_[i]:
                print "cons", i

    def get_args(self, state):
        return state.solver.eval(self.arg1, cast_to=str)[0:self.last_char_checked+1]

    def print_args(self, state):
        for i in state.solver.eval_upto(self.arg1, 10, cast_to=str):
            log(repr(i[0:self.last_char_checked+1])) #.strip('\x00\xff')))


prog = Program(sys.argv[1])#'./bin/pexpr')
status = None
state = None
with open("results.xt", "w+") as f:
    while True:
        prog.update_constraints()
        status, state = prog.gen_chains()
        print status
        prog.print_args(state)
        if status == 'success':
            print >>f, prog.get_args(state)
            f.flush()
        log("remaining: %d" % len(prog.states))
        if not prog.states:
            print "No more states"
            break
        prog.state = prog.states.pop()

#embed(globals(), locals(), configure=configure)

# state = prog.gen_chains()
# print("----------------")
# cdb = prog.get_constraint_db(prog.state)
# for i in cdb: print i, cdb[i]
# embed(globals(), locals(), configure=configure)
# #for i in state.solver.eval_upto(prog.arg1, 10, cast_to=str):
# #    log(i)
# state1 = prog.gen_chains(state)
# embed(globals(), locals())
