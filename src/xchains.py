#!/usr/bin/env python

import sys
import time
import angr
import random
import claripy
from ptpython.repl import embed

random.seed(sys.argv[2])

Max_Input_Len = 10000

def log(v): print "\t", v
def configure(repl): repl.confirm_exit = False

class Program:
    def __init__(self, exe):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        arg1k = ['sym_arg_%s' % str(i) for i in range(0, Max_Input_Len)]
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]

        # self.arg1 = claripy.BVS('sym_arg', 8 * )
        self.arg1 = reduce(lambda x,y: x.concat(y), self.arg1a)
        self.istate = self.project.factory.entry_state(args=[exe, self.arg1])

        # make first character printable.
        self.make_printable(self.arg1a[0])

        self.cfg = self.project.analyses.CFG(fail_fast=True)
        self.success_fn = self.getFuncAddr('success')

        self.last_constraint_len = len(self.istate.solver.constraints)
        self.state = self.istate

        self.icdb = self.get_constraint_db(self.state)
        self.cdb = self.icdb
        self.states = []
        self.extra_states = []

        self.last_char_checked = 0
        self.update_checked_char()

    def update_checked_char(self):
        assert self.state.solver.min(self.arg1a[0]) > 31
        for i in range(self.last_char_checked+1, Max_Input_Len):
            v = self.state.solver.min(self.arg1a[i])
            if v > 31:
                self.last_char_checked = i
                print "XXXXXXXXXXXXXXXx  update self.last_char_checked %d: %d:%s" % (i, v,chr(v))
            else:
                break

    def retrieve_char_constraints(self, state):
        constraints = {}
        return [state.solver.variables(c) for c in state.solver.constraints]

    def make_printable(self, char):
        self.istate.add_constraints(char < 128)
        self.istate.add_constraints(char > 31)

    def getFuncAddr(self, fname):
        found = [addr for addr,func in self.cfg.kb.functions.iteritems()
                if fname == func.name]
        if len(found) > 0:
            assert len(found) == 1
            log("Found "+fname+"'s address at "+hex(found[0])+"!")
            return found[0]
        else:
            raise Exception("No address found for function : "+fname)

    def pop_what(self, states):
        assert states
        i = random.randint(0, len(states)-1)
        state = states.pop(i)

        # TODO: what we want to do here:
        # if the state is tainted,
        # duplicate the state, (in here, do not delete the state from states)
        # solve the last constraint added, and add the solution to the
        # one of the duplicate states, then continue with it
        # add (not solution) to the other duplicate state, and keep it
        # in the stack.
        #if is_tainted(state):
        #else:
        self.state = state
        self.states = states
        return state, states

    def print_constraints(self):
        for i,c in enumerate(self.state.solver.constraints):
            v = list(self.state.solver.variables(c))
            print "?\t", i, c, str(v)

    def gen_chains(self, state=None):
        states = self.states if self.states else []
        num = 0
        if not state: state = self.state
        while True:
            try:
                # log("%d states: %d constraints: %d" % (num, len(states), len(state.solver.constraints)))
                num += 1
                if state.addr == self.success_fn:
                    return ('success',state)
                succ = state.step()
                my_succ = succ.successors
                l = len(my_succ)
                # log("successors: %d" % l)
                # time.sleep(1)
                if l == 0:
                    # No active successors. Go back one step
                    log("..")
                    # update the last char checked here.
                states.extend(my_succ)
                ls = len(states)
                if ls == 0:
                    return ('no_states', None)

                state, states = self.pop_what(states)
                # self.print_constraints()

                # were there any new chars?
                if self.last_char_checked < Max_Input_Len - 1 and self.state.solver.min(self.arg1a[self.last_char_checked+1]) > 31:
                # were there any constraints?
                #if len(state.solver.constraints) > self.last_constraint_len:
                    print "new constraints: %d" % (len(state.solver.constraints) - self.last_constraint_len)

                    self.last_constraint_len = len(state.solver.constraints)
                    if self.states:
                        self.extra_states.append(self.states)
                    self.states = []
                    self.update_checked_char()
                    return ('constraint_update', self.state)
            except angr.errors.SimUnsatError, ue:
                log('unsat.. %s' % str(ue))
                state, states = self.pop_what(states)

    def get_constraint_db(self, state):
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
                    log("? %s" % i)
        return constraint_db

    def update_constraints(self):
        cdb_ = self.cdb
        self.cdb = self.get_constraint_db(self.state)
        for i in self.icdb:
            if self.cdb[i] > cdb_[i]:
                print "cons", i

    def print_current_args(self):
        for i in self.state.solver.eval_upto(self.arg1, 1, cast_to=str):
            log(repr(i.strip('\x00\xff')))


prog = Program(sys.argv[1])#'./bin/pexpr')
status = None
state = None
for i in range(1000):
    print(i)
    prog.update_constraints()
    status, state = prog.gen_chains()
    if status == 'success': break
    if not state:
        prog.print_current_args()
        print prog.last_char_checked
        states = prog.extra_states[-1]
        prog.state = states.pop()
        prog.states = states
        prog.update_checked_char()
        print prog.last_char_checked
        #time.sleep(10)

    print "status:", status
    # prog.print_constraints()
    prog.print_current_args()
    if len(prog.states) > 2000:
        print "states > 2000"
        embed(globals(), locals(), configure=configure)
    #time.sleep(1)
print "loop done"
prog.print_current_args()
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
