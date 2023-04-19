#!/usr/bin/env python3

import datetime as dt
import glob
import multiprocessing as mp
import os
import subprocess as sp
import sys
import typing as T

INPUT = "/Scratch/rs266/MP-H/"
OUTPUT = "/Scratch/rs266/MP-H/Attack-Counts-Single-IP/"

STDERR_LOCK = mp.Lock()


def log(message: str):
    with STDERR_LOCK:
        print(f"{dt.datetime.now()}: ", message, file=sys.stderr)


def run(output_base: str, files: T.Tuple[str, ...]) -> None:
    log(f"Starting {output_base}...")

    with open(
        os.path.join(OUTPUT, f"{output_base}.counts.psv"),
        "w",
        encoding="UTF-8",
    ) as data_file, open(
        os.path.join(OUTPUT, f"{output_base}.counts.log"),
        "w",
        encoding="UTF-8",
    ) as log_file:
        sp.run(
            [
                "python3",
                "-OO",
                "rav_attack_count.py",
                "--use-seconds-per-window",
                "--sensor-addresses",
                "200.19.107.238",
                *files,
            ],
            check=False,
            stdout=data_file,
            stderr=log_file,
        )

    log(f"Finished {output_base}.")


def main() -> int:
    log("Gathering files...")
    files = {
        f"{year}-{month:02d}-{day:02d}": glob.glob(
            os.path.join(INPUT, f"{year}/{year}-{month:02d}-{day:02d}T*Z.gz"),
            recursive=True,
        )
        for year in range(2018, 2024)
        for month in range(1, 13)
        for day in range(1, 32)
    }

    files = {key: value for key, value in files.items() if value}

    os.makedirs(OUTPUT, mode=770, exist_ok=True)

    log("Beginning processing...")
    with mp.Pool((os.cpu_count() or 16) // 3) as pool:
        pool.starmap(run, files.items())

    log("Finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
