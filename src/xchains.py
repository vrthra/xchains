#!/usr/bin/env python

import sys
import os
import time
import angr
import random
import claripy
from ptpython.repl import embed


Max_Input_Len = int(os.environ.get('MAX_INPUT', '10'))
Random_Seed = int(os.environ.get('R', '0'))
random.seed(Random_Seed)

def log(v): print >>sys.stderr, "\t", v
def configure(repl): repl.confirm_exit = False

class Program:
    def __init__(self, exe):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        arg1k = ['sym_arg_%s' % str(i) for i in range(0, Max_Input_Len+1)]
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]


        # self.arg1 = claripy.BVS('sym_arg', 8 * )
        self.arg1 = reduce(lambda x,y: x.concat(y), self.arg1a)
        self.istate = self.project.factory.entry_state(args=[exe, self.arg1])

        # make first character printable.
        # self.make_printable(self.arg1a[0])

        # make sure that we try a maximum of 10 chars
        self.istate.add_constraints(self.arg1a[Max_Input_Len] == 0)
        # for i in range(Max_Input_Len-1):
        #     self.make_printable(self.arg1a[i])

        self.cfg = self.project.analyses.CFG(fail_fast=True)
        self.success_fn = self.getFuncAddr('success')

        self.last_constraints = " && ".join([str(i) for i in self.istate.solver.constraints])
        self.state = self.istate

        self.icdb = self.get_constraint_db(self.state)
        self.cdb = self.icdb
        self.states = []

        self.last_char_checked = 0
        self.update_checked_char()

    def stack_depth(self, state):
        stk = state.callstack
        i = 0
        while stk:
            stk = stk.next
            i += 1
        return i

    def update_checked_char(self):
        print "\t last:", self.last_char_checked
        # assert self.state.solver.min(self.arg1a[0]) > 31
        for i in range(self.last_char_checked+1, Max_Input_Len):
            v = self.state.solver.min(self.arg1a[i])
            if v > 31:
            #if not self.state.solver.solution(self.arg1a[i], 0):
                self.last_char_checked = i
                #print "XXXXXXXXXXXXXXXx  update self.last_char_checked %d: %d:%s" % (i, v,chr(v))
            else:
                break

    def retrieve_char_constraints(self, state):
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
        return state, states

    def print_constraints(self):
        for i,c in enumerate(self.state.solver.constraints):
            v = list(self.state.solver.variables(c))
            print "\t?", i, c, str(v)

    def gen_chains(self, state=None):
        states = self.states if self.states else []
        num = 0
        if not state: state = self.state
        while True:
            try:
                # log("%d states: %d constraints: %d" % (num, len(states), len(state.solver.constraints)))
                num += 1
                if state.addr == self.success_fn: return ('success',state)
                my_succ = state.step().flat_successors # succ.successors for symbolic
                # TODO: which succ to expand? It is here that we should randomize.
                nsucc = len(my_succ)
                # time.sleep(1)
                if nsucc == 0:
                    log(".. %d" % len(states)) # No active successors. Go back one step -- verify if we can sat
                    self.last_char_checked = 0
                    self.update_checked_char()
                    if not states: return ('no_states', None)
                    state = states[-1]
                    states.pop()
                    #state, states = self.pop_what(states)
                    self.state = state
                    self.states = states
                elif nsucc > 1:
                    prog.print_current_args()
                    log("successors: %d" % nsucc)
                    state, ss = self.pop_what(my_succ)
                    states.extend(ss)
                    self.states = states
                    self.state = state
                    # self.print_constraints()
                    log("")
                else:
                    sys.stderr.write(".")
                    state = my_succ[0]
                    continue

                # were there any new chars?
                m = state.solver.min(self.arg1a[self.last_char_checked+1])
                last_constraints = " && ".join([str(i) for i in state.solver.constraints])
                if last_constraints != self.last_constraints:
                    self.last_constraints = last_constraints
                    # were there any constraints?
                    log("new constraints")
                    if self.last_char_checked < Max_Input_Len - 1 and m > 31 and m < 128:
                        log("adding: %s at %d" % (chr(m), self.last_char_checked))
                        self.states = []
                        self.update_checked_char()

                        # now concretize
                        # TODO: save the state with opposite constraints after
                        # checking unsat
                        val = state.solver.eval(self.arg1a[self.last_char_checked])
                        print "-----> %s" % chr(val)
                        # # not_state = state.copy()
                        # # not_state.add_constraints(self.arg1a[self.last_char_checked] != val)
                        # # not_state.simplify()
                        # # self.states.append(not_state)

                        # # state.add_constraints(self.arg1a[self.last_char_checked] == val)
                        # # state.simplify()
                        # embed(globals(), locals(), configure=configure)
                        self.last_constraints = " && ".join([str(i) for i in state.solver.constraints])
                    else:
                        log("->ignored")
            except angr.errors.SimUnsatError, ue:
                log('unsat.. %s' % str(ue))
                if not states: return (None, None)
                state = states[-1]
                states.pop()
                # state, states = self.pop_what(states)

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

    def get_current_args(self):
        return self.state.solver.eval(self.arg1, cast_to=str)[0:self.last_char_checked]

    def print_current_args(self):
        for i in self.state.solver.eval_upto(self.arg1, 10, cast_to=str):
            log(repr(i[0:self.last_char_checked])) #.strip('\x00\xff')))


prog = Program(sys.argv[1])#'./bin/pexpr')
status = None
state = None
with open("results.xt", "w+") as f:
    while True:
        prog.update_constraints()
        status, state = prog.gen_chains()
        print status
        prog.print_current_args()
        print >>f, prog.get_current_args()
        f.flush()
        log("remaining: %d" % len(prog.states))
        if not prog.states: break
        prog.state = prog.states.pop()

# for i in range(1000):
#     print(i)
#     prog.update_constraints()
#     status, state = prog.gen_chains()
#     if status == 'success': break
#     if not state:
#         prog.print_current_args()
#         print "1 last_char_checked:", prog.last_char_checked
#         assert len(prog.extra_states) > 0
#         # TODO: order by callstack depth
#         print repr(prog.extra_states)
#         states = prog.extra_states.pop()
#         s = sorted(states, lambda x, y: cmp(prog.stack_depth(x), prog.stack_depth(y)))
#         print ">>>", len(s), prog.stack_depth(s[0]), prog.stack_depth(s[-1])
#         prog.state = s.pop()
#         prog.states = s
#         prog.update_checked_char()
#         print "2 last_char_checked:", prog.last_char_checked
#         #time.sleep(10)
# 
#     print "status:", status
#     # prog.print_constraints()
#     prog.print_current_args()
#     if len(prog.states) > 2000:
#         print "states > 2000"
#         embed(globals(), locals(), configure=configure)
#     #time.sleep(1)
# print "loop done"
# prog.print_current_args()
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
