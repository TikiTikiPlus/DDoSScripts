#!/usr/bin/env python3
import datetime as dt
import multiprocessing as mp
import os
import sys
import typing as T

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker

PATH = "/Scratch/rs266/MP-H/Attack-Counts-New-Kids/"
START = dt.datetime(2018, 9, 1, tzinfo=dt.timezone.utc)
END = dt.datetime(2020, 9, 22, tzinfo=dt.timezone.utc)

PROTOCOL_NAMES = {  # Some of the service/protocol names recognised here.
    17: "QOTD",
    19: "CHARGEN",
    53: "DNS",
    123: "NTP",
    161: "SNMP",
    389: "CLDAP",
    1900: "SSDP",
    5683: "CoAP",
    11211: "Memcached",
    **dict.fromkeys(range(27000, 27015 + 1), "Steam"),
}


def request_count(file_path: str):
    protocol: T.Dict[str, int] = {}
    with open(file_path, "r", encoding="UTF-8") as file:
        for line in file:
            if line[0] != "#":
                splitted = line.rstrip().split("|")
                if splitted[3] in PROTOCOL_NAMES.values():
                    if splitted[3] in protocol:
                        protocol[splitted[3]] += int(splitted[5])
                    else:
                        protocol[splitted[3]] = int(splitted[5])
    return protocol

def attack_count(file_path: str):
    protocol: T.Dict[str, int] = {}
    with open(file_path, "r", encoding="UTF-8") as file:
        for line in file:
            if line[0] != "#":
                splitted = line.rstrip().split("|")
                if splitted[3] in PROTOCOL_NAMES.values():
                    if splitted[3] in protocol:
                        protocol[splitted[3]] += 1
                    else:
                        protocol[splitted[3]] = 1
    return protocol


def main() -> int:
    dated_files: T.Dict[dt.datetime, str] = {}
    for file_name in os.listdir(PATH):
        if file_name.endswith(".counts.psv"):
            date = dt.datetime.strptime(
                file_name, "%Y-%m-%d.counts.psv"
            ).replace(tzinfo=dt.timezone.utc)
            if START <= date <= END:
                dated_files[date] = os.path.join(PATH, file_name)

    files: T.List[str] = []
    dates: T.List[dt.datetime] = []

    for dated, file_path in tuple(
        sorted(dated_files.items(), key=lambda x: x[0])
    ):
        files.append(file_path)
        dates.append(dated)

    with mp.Pool(os.cpu_count() or 8) as pool:
        counters = pool.map(attack_count, files)

    total = sum(count for protocol in counters for count in protocol.values())
    print(f"Total requests: {total:,}")

    protocols: T.Dict[str, T.Dict[dt.datetime, int]] = {}
    for counter, date in zip(counters, dates):
        month = date.replace(day=1)

        for protocol, count in counter.items():
            if protocol not in protocols:
                protocols[protocol] = {}
            if month not in protocols[protocol]:
                protocols[protocol][month] = 0
            protocols[protocol][month] += count

    plt.xlabel("month")
    plt.ylabel("# requests")
    plt.xlim(
        dt.datetime(2018, 9, 1, tzinfo=dt.timezone.utc),
        dt.datetime(2020, 9, 28, tzinfo=dt.timezone.utc),
    )
    plt.xticks(rotation=90)
    plt.title("Evolution of monthly requests (overall).")

    xaxis = plt.gca().xaxis
    xaxis.set_major_locator(
        mdates.MonthLocator(interval=1, tz=dt.timezone.utc)
    )
    xaxis.set_major_formatter(
        mdates.DateFormatter("%Y-%m", tz=dt.timezone.utc)
    )


    # def human_format(x, _):
    #     return f"{x * 1e-6:.0f}M"

    # plt.gca().yaxis.set_major_formatter(
    #     matplotlib.ticker.FuncFormatter(human_format)
    # )

    for protocol, months in protocols.items():
        plt.bar(list(months), list(months.values()), width=25, align="center")

    plt.legend(protocols.keys(), loc="upper left")

    plt.show()
    return 0


if __name__ == "__main__":
    sys.exit(main())
