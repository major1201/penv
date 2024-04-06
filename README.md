# penv

Modify environment variable of a running process

## Usage

```
# ./penv -h
Usage: penv [options] - put env on another process
Options:
    -h              print this help
    -p <pid>        pid to modify env
    -e <env_str>    env str in format: <name>=<value>
    -m <mode>       set mode, only_this_one|rebuild_environ
                      - only_this_one: just like putenv() or setenv()
                      - rebuild_environ: rebuild the whole environ and reset the
                        /proc/<pid>/environ memory address
                    default: in_place for equal value length, otherwise only_this_one
```

Examples

```bash
penv -p 1234 -e "NAME=new_env_value"

# force set mode
penv -p 1234 -e "NAME=new_env_value" -m rebuild_environ
```
