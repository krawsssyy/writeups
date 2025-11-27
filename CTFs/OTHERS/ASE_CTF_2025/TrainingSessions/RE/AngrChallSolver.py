import angr
import claripy

BINARY = "./z3chall"

def main():
    proj = angr.Project(BINARY, auto_load_libs=False)

    # model password
    pw = [claripy.BVS(f"p{i}", 8) for i in range(8)]
    pw_concat = claripy.Concat(*pw)

    # create initial state with stdin = passwd + newline
    state = proj.factory.full_init_state(
        stdin=pw_concat
    )

    # enforce ascii
    for b in pw:
        state.solver.add(b >= 32)
        state.solver.add(b <= 126)

    simgr = proj.factory.simulation_manager(state) # init sim manager

    # define success/failure condition
    def is_success(s):
        out = s.posix.dumps(1)
        return b"Correct password!" in out

    def is_failure(s):
        out = s.posix.dumps(1)
        return b"Nope" in out or b"Wrong length!" in out

    # run sim
    simgr.explore(find=is_success, avoid=is_failure)

    if simgr.found:
        good = simgr.found[0]
        solution = good.solver.eval(pw_concat, cast_to=bytes)
        print("Password:", solution.decode())
    else:
        print("No solution :(")

if __name__ == "__main__":
    main()
