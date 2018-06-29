#!/usr/bin/env python

import sys
import time
import angr
import random
import claripy
from ptpython.repl import embed

Max_Input_Len = 10

def log(v): print(v)

class Program:
    def __init__(self, exe):
        self.exe = exe
        # Use auto_load_libs = False to use symbolic summaries of libs
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})
        self.arg1a = [claripy.BVS('sym_arg_%s' % str(i), 8)
                for i in range(0, Max_Input_Len)]

        # self.arg1 = claripy.BVS('sym_arg', 8 * )
        self.arg1 = reduce(lambda x,y: x.concat(y), self.arg1a)
        self.istate = self.project.factory.entry_state(args=[exe, self.arg1])
        for c in self.arg1a: self.make_printable(c)

        self.cfg = self.project.analyses.CFG(fail_fast=True)
        self.success_fn = self.getFuncAddr('success')

    def make_printable(self, char):
        self.istate.add_constraints(char < 128)
        self.istate.add_constraints(char > 32)

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
        i = random.randint(0, len(states)-1)
        state = states[i]
        states.pop(i)

        # TODO: what we want to do here:
        # if the state is tainted,
        # duplicate the state, (in here, do not delete the state from states)
        # solve the last constraint added, and add the solution to the
        # one of the duplicate states, then continue with it
        # add (not solution) to the other duplicate state, and keep it
        # in the stack.
        #if is_tainted(state):
        #else:
        return state, states

    def gen_chains(self, state=None):
        states = []
        i = 0
        if not state: state = self.istate
        while True:
            log("%d states: %d constraints: %d" % (i, len(states), len(state.solver.constraints)))
            i += 1
            if state.addr == self.success_fn: return state
            succ = state.step()
            my_succ = succ.successors
            l = len(my_succ)
            log("successors: %d" % l)
            time.sleep(1)
            if l == 0:
                # No active successors. Go back one step
                log("..")
            states.extend(my_succ)
            ls = len(states)
            if ls == 0:
                return None
            #elif ls == 1:
            #    state = states[0]
            #    states.pop()
            else:
                state, states = self.pop_what(states)
                # were there any constraints?
                if len(state.solver.constraints) > 0:
                    # was it a constraint on input?
                    # then concretize the last constraint.
                    assert len(state.solver.constraints[-1].args) == 2
                    assert not state.solver.constraints[-1].args[0].concrete
                    assert state.solver.constraints[-1].args[1].concrete

                    bv = state.solver.constraints[-1].args[0]
                    for i in bv.recursive_children_asts:
                        if (repr(i) == repr(self.arg1.args[0])):
                            log("tainted")
                            return state


prog = Program('./bin/pexpr')
embed(globals(), locals())
state = prog.gen_chains()
log(state.solver.eval_upto(prog.arg1, 10, cast_to=str))
embed(globals(), locals())
