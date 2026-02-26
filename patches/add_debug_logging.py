#!/usr/bin/env python3
"""Patch rootless C and Go code with detailed stderr logging."""

import sys

C_PREFIX = "[debug:reexec_userns_join]"
GO_PREFIX = "[debug:TryJoinFromFilePaths]"


def patch_c(filepath: str):
    with open(filepath) as f:
        lines = f.readlines()

    out: list[str] = []
    in_func = False
    brace_depth = 0
    func_entered = False

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip("\n")
        content = stripped.lstrip()

        # Detect function definition (spans two lines in GNU style)
        if (
            not in_func
            and content == "int"
            and i + 1 < len(lines)
            and "reexec_userns_join" in lines[i + 1]
        ):
            in_func = True
            brace_depth = 0
            func_entered = False
            out.append(line)
            i += 1
            continue

        if in_func:
            brace_depth += content.count("{") - content.count("}")

            if not func_entered and content == "{":
                func_entered = True
                out.append(line)
                i += 1
                continue

            if func_entered and brace_depth == 0 and content == "}":
                in_func = False
                out.append(line)
                i += 1
                continue

            ind = line[: len(line) - len(line.lstrip())]

            # --- insertion points ------------------------------------------------

            # After last variable declaration, before first statement
            if "cwd = getcwd (NULL, 0);" in content:
                _emit_entry_log(out, ind)
                out.append(line)
                i += 1
                continue

            # After opening user namespace
            if "userns_fd = open_namespace (pid_to_join" in content:
                out.append(line)
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' open_namespace(user) fd=%d%s\\n",'
                    f' userns_fd, userns_fd < 0 ? " FAILED" : "");'
                ))
                i += 1
                continue

            # After opening mnt namespace
            if "mntns_fd = open_namespace (pid_to_join" in content:
                out.append(line)
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' open_namespace(mnt) fd=%d%s\\n",'
                    f' mntns_fd, mntns_fd < 0 ? " FAILED" : "");'
                ))
                i += 1
                continue

            # Before fork
            if "pid = fork ();" in content:
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX} forking ...\\n");'
                ))
                out.append(line)
                i += 1
                continue

            # Parent returning
            if content == "return pid;":
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' parent returning child_pid=%d\\n", pid);'
                ))
                out.append(line)
                i += 1
                continue

            # Before joining user namespace
            if 'join_namespace_or_die ("user"' in content:
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: joining user ns (fd=%d)'
                    f' for pid %d\\n", userns_fd, pid_to_join);'
                ))
                out.append(line)
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: joined user ns OK\\n");'
                ))
                i += 1
                continue

            # Before joining mnt namespace
            if 'join_namespace_or_die ("mnt"' in content:
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: joining mnt ns (fd=%d)'
                    f' for pid %d\\n", mntns_fd, pid_to_join);'
                ))
                out.append(line)
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: joined mnt ns OK\\n");'
                ))
                i += 1
                continue

            # Before setresgid
            if "syscall_setresgid (0, 0, 0)" in content:
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: setresgid(0,0,0)\\n");'
                ))
                out.append(line)
                i += 1
                continue

            # Before setresuid
            if "syscall_setresuid (0, 0, 0)" in content:
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: setresuid(0,0,0)\\n");'
                ))
                out.append(line)
                i += 1
                continue

            # Before create_pause_process
            if "create_pause_process (pause_pid_file_path" in content:
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: create_pause_process(%s)\\n",'
                    f' pause_pid_file_path);'
                ))
                out.append(line)
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: create_pause_process returned\\n");'
                ))
                i += 1
                continue

            # Before execvp
            if 'execvp ("/proc/self/exe"' in content:
                _emit(out, ind, (
                    f'fprintf (stderr, "{C_PREFIX}'
                    f' child: execvp /proc/self/exe\\n");'
                ))
                out.append(line)
                i += 1
                continue

        out.append(line)
        i += 1

    with open(filepath, "w") as f:
        f.writelines(out)

    print(f"Patched {filepath}")


def _emit(out: list[str], indent: str, code: str):
    """Append a single indented C statement."""
    out.append(f"{indent}{code}\n")


def _emit_entry_log(out: list[str], ind: str):
    """Emit the entry-point debug block (fprintf + /proc/pid/cmdline read)."""
    _emit(out, ind, (
        f'fprintf (stderr, "{C_PREFIX}'
        f' entering: pid_to_join=%d,'
        f' pause_pid_file_path=\\"%s\\"\\n",'
        f' pid_to_join,'
        f' pause_pid_file_path ? pause_pid_file_path : "(null)");'
    ))
    # Read /proc/<pid>/cmdline to identify what process lives at that PID
    out.append(f"{ind}{{\n")
    out.append(f"{ind}  char _dbg_path[64], _dbg_buf[256];\n")
    out.append(f"{ind}  int _dbg_fd; ssize_t _dbg_n;\n")
    out.append(
        f'{ind}  snprintf (_dbg_path, sizeof (_dbg_path),'
        f' "/proc/%d/cmdline", pid_to_join);\n'
    )
    out.append(f"{ind}  _dbg_fd = open (_dbg_path, O_RDONLY);\n")
    out.append(f"{ind}  if (_dbg_fd >= 0)\n")
    out.append(f"{ind}    {{\n")
    out.append(
        f"{ind}      _dbg_n = read (_dbg_fd, _dbg_buf,"
        f" sizeof (_dbg_buf) - 1);\n"
    )
    out.append(f"{ind}      close (_dbg_fd);\n")
    out.append(f"{ind}      if (_dbg_n > 0)\n")
    out.append(f"{ind}        {{\n")
    out.append(f"{ind}          int _j;\n")
    out.append(f"{ind}          _dbg_buf[_dbg_n] = '\\0';\n")
    out.append(f"{ind}          for (_j = 0; _j < _dbg_n; _j++)\n")
    out.append(
        f"{ind}            if (_dbg_buf[_j] == '\\0')"
        f" _dbg_buf[_j] = ' ';\n"
    )
    out.append(
        f'{ind}          fprintf (stderr, "{C_PREFIX}'
        f' pid %d cmdline: %s\\n",'
        f' pid_to_join, _dbg_buf);\n'
    )
    out.append(f"{ind}        }}\n")
    out.append(f"{ind}    }}\n")
    out.append(f"{ind}  else\n")
    out.append(
        f'{ind}    fprintf (stderr, "{C_PREFIX}'
        f' cannot read cmdline for pid %d: %m\\n",'
        f' pid_to_join);\n'
    )
    out.append(f"{ind}}}\n")


def patch_go(filepath: str):
    """Patch TryJoinFromFilePaths in rootless_linux.go with debug logging."""
    with open(filepath) as f:
        content = f.read()

    P = GO_PREFIX

    # Ensure "fmt" and "os" are imported (they already are in this file,
    # but guard against future changes).
    if '"fmt"' not in content:
        content = content.replace(
            'import (', 'import (\n\t"fmt"', 1
        )

    old_func = '''\
func TryJoinFromFilePaths(pausePidPath string, paths []string) (bool, int, error) {
\tvar lastErr error

\tfor _, path := range paths {
\t\tdata, err := os.ReadFile(path)
\t\tif err != nil {
\t\t\tlastErr = err
\t\t\tcontinue
\t\t}

\t\tpausePid, err := strconv.Atoi(string(data))
\t\tif err != nil {
\t\t\tlastErr = fmt.Errorf("cannot parse file %q: %w", path, err)
\t\t\tcontinue
\t\t}

\t\tif pausePid > 0 && unix.Kill(pausePid, 0) == nil {
\t\t\tjoined, pid, err := joinUserAndMountNS(uint(pausePid), pausePidPath)
\t\t\tif err == nil {
\t\t\t\treturn joined, pid, nil
\t\t\t}
\t\t\tlastErr = err
\t\t}
\t}
\tif lastErr != nil {
\t\treturn false, 0, lastErr
\t}
\treturn false, 0, fmt.Errorf("could not find any running process: %w", unix.ESRCH)
}'''

    new_func = f'''\
func TryJoinFromFilePaths(pausePidPath string, paths []string) (bool, int, error) {{
\tfmt.Fprintf(os.Stderr, "{P} entering: pausePidPath=%s, paths=%v\\n", pausePidPath, paths)
\tvar lastErr error

\tfor _, path := range paths {{
\t\tfmt.Fprintf(os.Stderr, "{P} reading pid file: %s\\n", path)
\t\tdata, err := os.ReadFile(path)
\t\tif err != nil {{
\t\t\tfmt.Fprintf(os.Stderr, "{P} ReadFile(%s) error: %v\\n", path, err)
\t\t\tlastErr = err
\t\t\tcontinue
\t\t}}
\t\tfmt.Fprintf(os.Stderr, "{P} read data from %s: %q\\n", path, string(data))

\t\tpausePid, err := strconv.Atoi(string(data))
\t\tif err != nil {{
\t\t\tfmt.Fprintf(os.Stderr, "{P} Atoi(%q) error: %v\\n", string(data), err)
\t\t\tlastErr = fmt.Errorf("cannot parse file %q: %w", path, err)
\t\t\tcontinue
\t\t}}
\t\tfmt.Fprintf(os.Stderr, "{P} parsed pid=%d from %s\\n", pausePid, path)

\t\tkillErr := unix.Kill(pausePid, 0)
\t\tfmt.Fprintf(os.Stderr, "{P} kill(%d, 0) = %v (nil means alive)\\n", pausePid, killErr)

\t\tif pausePid > 0 && killErr == nil {{
\t\t\tprocCmdline := fmt.Sprintf("/proc/%d/cmdline", pausePid)
\t\t\tif cmdline, err := os.ReadFile(procCmdline); err == nil {{
\t\t\t\tfor i := range cmdline {{
\t\t\t\t\tif cmdline[i] == 0 {{
\t\t\t\t\t\tcmdline[i] = ' '
\t\t\t\t\t}}
\t\t\t\t}}
\t\t\t\tfmt.Fprintf(os.Stderr, "{P} pid %d cmdline: %s\\n", pausePid, string(cmdline))
\t\t\t}} else {{
\t\t\t\tfmt.Fprintf(os.Stderr, "{P} cannot read cmdline for pid %d: %v\\n", pausePid, err)
\t\t\t}}

\t\t\tfmt.Fprintf(os.Stderr, "{P} calling joinUserAndMountNS(pid=%d, pausePidPath=%s)\\n", pausePid, pausePidPath)
\t\t\tjoined, pid, err := joinUserAndMountNS(uint(pausePid), pausePidPath)
\t\t\tfmt.Fprintf(os.Stderr, "{P} joinUserAndMountNS returned: joined=%v, pid=%d, err=%v\\n", joined, pid, err)
\t\t\tif err == nil {{
\t\t\t\treturn joined, pid, nil
\t\t\t}}
\t\t\tlastErr = err
\t\t}} else {{
\t\t\tfmt.Fprintf(os.Stderr, "{P} skipping pid %d (pid<=0 or not alive)\\n", pausePid)
\t\t}}
\t}}
\tif lastErr != nil {{
\t\tfmt.Fprintf(os.Stderr, "{P} returning lastErr: %v\\n", lastErr)
\t\treturn false, 0, lastErr
\t}}
\tfmt.Fprintf(os.Stderr, "{P} no running process found\\n")
\treturn false, 0, fmt.Errorf("could not find any running process: %w", unix.ESRCH)
}}'''

    if old_func not in content:
        # Try with spaces instead of tabs (in case the file uses spaces)
        old_func_spaces = old_func.replace("\t", " ")
        if old_func_spaces in content:
            new_func_spaces = new_func.replace("\t", " ")
            content = content.replace(old_func_spaces, new_func_spaces, 1)
        else:
            print(f"WARNING: could not find TryJoinFromFilePaths in {filepath}")
            print("Attempting line-by-line fallback...")
            content = _patch_go_fallback(content)
    else:
        content = content.replace(old_func, new_func, 1)

    with open(filepath, "w") as f:
        f.write(content)

    print(f"Patched {filepath}")


def _patch_go_fallback(content: str) -> str:
    """Fallback: inject debug lines around key statements in TryJoinFromFilePaths."""
    P = GO_PREFIX
    lines = content.split("\n")
    out: list[str] = []
    in_func = False
    brace_depth = 0

    for line in lines:
        stripped = line.strip()

        if "func TryJoinFromFilePaths(" in stripped:
            in_func = True
            brace_depth = 0
            out.append(line)
            continue

        if in_func:
            brace_depth += stripped.count("{") - stripped.count("}")

            if brace_depth <= 0 and stripped == "}":
                in_func = False
                out.append(line)
                continue

            ind = line[: len(line) - len(line.lstrip())]

            if "var lastErr error" in stripped:
                out.append(
                    f'{ind}fmt.Fprintf(os.Stderr,'
                    f' "{P} entering: pausePidPath=%s,'
                    f' paths=%v\\n", pausePidPath, paths)'
                )

            if "data, err := os.ReadFile(path)" in stripped:
                out.append(
                    f'{ind}fmt.Fprintf(os.Stderr,'
                    f' "{P} reading pid file: %s\\n", path)'
                )

            if "joinUserAndMountNS(uint(pausePid)" in stripped:
                out.append(
                    f'{ind}fmt.Fprintf(os.Stderr,'
                    f' "{P} calling joinUserAndMountNS'
                    f'(pid=%d)\\n", pausePid)'
                )

        out.append(line)

    return "\n".join(out)


if __name__ == "__main__":
    patch_c(sys.argv[1])
    patch_go(sys.argv[2])
