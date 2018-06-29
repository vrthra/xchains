import sys
import time
import angr
import random
import claripy
Max_Input_Len = 10
def getFuncAddress(funcName, cfg, plt=None):
    found = [addr for addr,func in cfg.kb.functions.iteritems()
            if funcName == func.name and (plt is None or func.is_plt == plt)]
    if len( found ) > 0:
        print "Found "+funcName+"'s address at "+hex(found[0])+"!"
        return found[0]
    else:
        raise Exception("No address found for function : "+funcName)


def loadexe(s):
    p = angr.Project(s, load_options={'auto_load_libs':False}) # use symbolic summary
    #p = angr.Project(s, load_options={'auto_load_libs':True}) # do not use symbolic summary
    arg1 = claripy.BVS('sym_arg_0', 8)
    my_args = [arg1]
    for i in range(1, Max_Input_Len):
        a = claripy.BVS('sym_arg_%s' % str(i), 8)
        my_args.append(a)
        arg1 = arg1.concat(a)
    #arg1 = claripy.BVS('sym_arg', 8 * Max_Input_Len)
    state = p.factory.entry_state(args=[s, arg1])

    # make all ascii printable
    for a in my_args:
        state.add_constraints(a > 31)
        state.add_constraints(a < 128)
    return (p, state, arg1, my_args)



def stepthrough(state):
    while True:
        succ = state.step()
        if len(succ.successors) == 0: return (state, succ.successors)
        if len(succ.successors) > 1: return (state, succ.successors)
        state = succ.successors[0]


def choose_first(state):
    while True:
        state1, succ = stepthrough(state)
        if len(succ) == 0:
            return state1
        state = succ[0]

def pop_what_last(states):
    state = states[-1]
    states.pop()
    return state, states

def is_tainted(state):
    global arg1
    # were there any constraints?
    if len(state.solver.constraints) > 0:
        # was it a constraint on input?
        # then concretize the last constraint.
        assert len(state.solver.constraints[-1].args) == 2
        assert not state.solver.constraints[-1].args[0].concrete
        assert state.solver.constraints[-1].args[1].concrete

        bv = state.solver.constraints[-1].args[0]
        for i in bv.recursive_children_asts:
            if (i.args[0] == arg1.args[0]):
                print "tainted"
                return True
    return False

def pop_what_random(states):
    i = random.randint(0,len(states)-1)
    state = states[i]
    # TODO: what we want to do here:
    # if the state is tainted,
    # duplicate the state, (in here, do not delete the state from states)
    # solve the last constraint added, and add the solution to the
    # one of the duplicate states, then continue with it
    # add (not solution) to the other duplicate state, and keep it
    # in the stack.
    #if is_tainted(state):
    #else:
    states.pop(i)


    return state, states

def pop_what(states):
    return pop_what_random(states)
    #return pop_what_last(states)

def choose_stack(success, state):
    states = []
    global arg1
    chops = arg1.chop(8)
    i = 0
    while True:
        print i, "states:", len(states),  "Constraints", len(state.solver.constraints)
        i += 1
        if state.addr == success:
            print "success"
            return state
        succ = state.step()
        my_succ = succ.successors
        l = len(my_succ)
        #print "%d choices" % l
        if l == 0:
            # No active successors. is success found?
            if state.addr == success:
                print "success"
                return state
            else:
                print ".."
        states.extend(my_succ)
        ls = len(states)
        if ls == 0:
            return None
        #elif ls == 1:
        #    state = states[0]
        #    states.pop()
        else:
            state, states = pop_what(states)
            # were there any constraints?
            if len(state.solver.constraints) > 0:
                # was it a constraint on input?
                # then concretize the last constraint.
                assert len(state.solver.constraints[-1].args) == 2
                assert not state.solver.constraints[-1].args[0].concrete
                assert state.solver.constraints[-1].args[1].concrete

                bv = state.solver.constraints[-1].args[0]
                for i in bv.recursive_children_asts:
                    if (repr(i) == repr(arg1.args[0])):
                        print "tainted"
                        return state
                #if list(state.solver.constraints[-1].args[0].variables)[0] == arg1.args[0]:
                #    print "tainted"

        #print
        #print "Input:",state.solver.eval(arg1, cast_to=str)
        #time.sleep(1)

def choose_random(state):
    states = []
    global arg1
    while True:
        state1, succ = stepthrough(state)
        print state1.solver.constraints
        print state1.solver.eval(arg1, cast_to=str)
        if len(succ) == 0:
            return state1


        l = len(succ)
        print "%d choices" % l
        i = random.randint(0,l-1)
        #state = random.choice(succ)
        print "chose %d" % i
        #states.extend(succ)
        #state = states[-1]
        #states.pop()
        state = succ[i]

p, state1, arg1, my_args = loadexe('./pexpr')
cfg = p.analyses.CFG(fail_fast=True)
success = getFuncAddress('_Z7successf', cfg)

from ptpython.repl import embed
embed(globals(), locals())
state = choose_stack(success, state1)
#sols = state.solver.eval_upto(arg1, 10, cast_to=str)
#for sol in sols:
#    print sol
print state.solver.eval(arg1, cast_to=str)
embed(globals(), locals())
sys.exit(0)

s = choose_random(state1)
print s.solver.constraints

#print s.solver.any_str(arg1)
print s.solver.eval(arg1, cast_to=str)

print s.solver.eval(arg1.chop(8)[0], cast_to=str)
print list(s.solver.constraints[0].args[0].variables)[0]
print s.solver.constraints[0].op
print s.solver.constraints[0].args[1]

print arg1.args[0] == list(s.solver.constraints[0].args[0].variables)[0]



# state.libc.max_strtol_len = 100
sm = p.factory.simulation_manager(state1)
sm.use_technique(angr.exploration_techniques.DFS())

print "start"
t1 = time.time()
res = sm.explore(find=success)
t2 = time.time()
print "This took %.2f seconds" % (t2 - t1)


# def run():
#     val = None
#     while len(sm.active) == 1:
#         val = sm.step()
#     return val
# 
# run()
# sm.move(from_stash='active', to_stash='authenticated', filter_func=lambda s: 'Welcome' in s.posix.dumps(1))
