from icmplib import ping, async_ping
from rich.pretty import pprint
import sys
from bs4 import BeautifulSoup as BS
import json
import subprocess
import os
import re
import secrets
import httpx
import typing as T
import asyncio
import uvloop
import time
import functools
import inspect

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


def must_be_root(func):
    """
    For commands that require being run as root
    Not used because I don't have a good way of scripting with it
    """

    @functools.wraps(func)
    def x():
        uid = os.getuid()
        if uid == 0:
            return func()
        else:
            raise Exception(uid, "is not root")

    return x


def check_for_leaks() -> bool:
    """Verifies that your connection is reasonably secure"""
    url = "https://am.i.mullvad.net/json"
    with httpx.Client() as client:
        res = client.get(url)
        data = res.json()
        if data["blacklisted"]["blacklisted"]:
            return False
        if not data["mullvad_exit_ip"]:
            return False
        return True


def remote_data():
    """"""
    url = "https://api.mullvad.net/www/relays/all/"
    with httpx.Client() as client:
        res = client.get(url)
        return res.json()


async def ping_all_hosts(data: list):
    """"""

    async def a(
        ip: str, hostname: str, city_code: str, country_code: str, vpn_proto: str
    ):
        if ":" in ip:
            family = 6
        else:
            family = 4
        res = await async_ping(
            ip,
            count=18,
            interval=0.8,
            timeout=4,
            id=None,
            source=None,
            family=family,
            privileged=False,
        )
        result = {
            "hostname": hostname,
            "city_code": city_code,
            "country_code": country_code,
            "vpn_proto": vpn_proto,
            "ipv4": ip,
            "is_alive": res.is_alive,
            "min_rtt": res.min_rtt,
            "avg_rtt": res.avg_rtt,
            "max_rtt": res.max_rtt,
            "packet_loss": res.packet_loss,
            "jitter": res.jitter,
        }
        return result

    ipv4s = list(
        map(
            lambda x: a(
                x["ipv4_addr_in"],
                x["hostname"],
                x["city_code"],
                x["country_code"],
                x["type"],
            ),
            data,
        )
    )
    # My main internet connection does not have ipv6 working, YAY
    # ipv6s = list(filter(None, list(map(lambda x: x["ipv6_addr_in"], data))))
    # ipv6ss = list(map(lambda x: a(x), ipv6s))
    ping4s = await asyncio.gather(*ipv4s)
    # ping6s = await asyncio.gather(*ipv6ss)
    alive = list(filter(lambda x: x["is_alive"], ping4s))
    pings = sorted(alive, key=lambda x: x["avg_rtt"])
    return pings


def get_():
    """"""
    l = remote_data()
    p = asyncio.run(ping_all_hosts(l))
    return p


def filter_vpns(
    protocol: str = "wireguard",
    avg_rtt: int = 180,
    max_rtt: int = 210,
    jitter: int = 5,
    packet_loss: float = 0.0,
):
    """"""
    options = get_()
    vpn_proto = list(filter(lambda x: (x["vpn_proto"] == protocol), options))
    packet_loss = list(filter(lambda x: (x["packet_loss"] <= packet_loss), vpn_proto))
    avg_less_then = list(filter(lambda x: (x["avg_rtt"] <= avg_rtt), packet_loss))
    max_less_then = list(filter(lambda x: (x["max_rtt"] <= max_rtt), avg_less_then))
    jitter_less_then = list(filter(lambda x: (x["jitter"] <= jitter), max_less_then))
    return jitter_less_then


def get_current_config() -> str:
    """"""
    cmd = ["wg show all endpoints"]
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    conf = res.stdout.decode("utf-8").split("\t")[0]
    return conf


def is_up() -> bool:
    """Checks if wg has any active connections"""
    config = get_current_config()
    if config == "":
        return False
    else:
        return True


def wg_up(config: str) -> bool:
    """"""
    cmd = ["wg-quick up " + config]
    try:
        res = subprocess.run(
            cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
    except Exception as e:
        raise Exception("up cmd failed")
        sys.exit(1)
    if res.returncode == 0:
        print(config, "is up")
        return True
    else:
        return False


def wg_down(config: str) -> bool:
    """"""
    cmd = ["wg-quick down " + config]
    try:
        res = subprocess.run(
            cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
    except Exception as e:
        raise Exception("Down cmd failed")
        sys.exit(1)
    if res.returncode == 0:
        print(config, "is down")
        return True
    else:
        return False


def get_all_configs() -> T.Union[list, bool]:
    """"""
    cmd = ["find /etc/wireguard -type f -name '*.conf'"]
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    except Exception as e:
        print(e)
        sys.exit(1)
    stdou = list(filter(None, res.stdout.decode("utf-8").split("\n")))
    if not stdou == "":
        basenames = list(map(os.path.basename, stdou))
        configs = list(map(lambda x: x[:-5], basenames))
        return configs
    else:
        return False


def get_random_config(fully_rand: bool = True) -> str:
    """"""
    if fully_rand:
        configs = get_all_configs()
    else:
        configs = filter_vpns()

    if configs:
        rand_conf = secrets.choice(configs)
        if rand_conf != get_current_config():
            print(rand_conf)
            return rand_conf
        else:
            # Should only recur once, so optimization is not a concern
            return get_random_config()


def rotate():
    """Switches to a new, random wireguard config"""
    if is_up():
        wg_down(get_current_config())

    conf = get_random_config()
    u = wg_up(conf)
    if u:
        print("Rotated successfully")
    else:
        print("Failed rotating")


def _local_cmds():
    """"""
    # List of all functions, including imported ones, in local module
    all_functions = list(filter(lambda x: callable(x[1]), list(globals().items())))
    # List of just the functions from this module
    local_functions = list(
        filter(lambda x: (x[1].__module__ == "__main__"), all_functions)
    )
    # List of all non-utility functions from this module
    facing_functions = list(
        filter(lambda x: (not re.match(r"^_.*", x[0])), local_functions)
    )
    # cli_cmds = list(map(lambda x: x[0], facing_functions))
    return facing_functions


def _help_cmds():
    """Extracts docstring from list of 2-tuples, name and func being the values"""
    cmds = _local_cmds()
    helps = list(map(lambda x: (x[0], x[1], inspect.getdoc(x[1])), cmds))
    return helps


def _exec_on_match(subcmd: str, func_tuple: tuple):
    """"""
    if subcmd == func_tuple[0]:
        func_tuple[1]()


def _help():
    pprint(_help_cmds)


def main(argv: list):
    cli_cmds = _help_cmds()
    subcmd = argv[1]
    cmds = list(map(lambda x: x[0], cli_cmds))
    pprint(cmds)
    cmd = list(filter(lambda x: (x[0] == subcmd), cli_cmds))
    if len(cmd) == 1:
        cmd[0][1](argv[2:])
    else:
        _help()


if __name__ == "__main__":
    main(sys.argv)
