#!/usr/bin/env python3
__author__ = "RavSS"

import argparse
import collections as cll
import dataclasses
import datetime as dt
import glob
import gzip
import ipaddress as ip  # Avoid using this too much.
import multiprocessing as mp
import multiprocessing.pool as mp_pool
import os
import sys
import typing as T


# This is a hack to make the default multiprocessing pool not spawn daemon
# processes; hence, we can then use pools within child processes made by a
# pool. Will cause a lot of zombie processes or fail to exit cleanly if
# something ancestral crashes, as they're no longer marked daemonic.
class NoDaemonProcess(mp.Process):
    @property
    def daemon(self):
        return False

    @daemon.setter
    def daemon(self, _):
        pass


class CustomPool(mp_pool.Pool):
    def Process(self, *args, **kwargs):
        proc = super().Process(*args, **kwargs)  # type: ignore
        proc.__class__ = NoDaemonProcess
        return proc


# Globals

# Splits a file into a (roughly) sized slice so we waste less time using a
# single core on a massive file, as files may vary heavily in length. The pool
# hack was for this. If this is too low, then a fork bomb essentially occurs.
# Set this to `None` to disable it.
# parser_slice_size: T.Optional[int] = 15 * 2**20  # 15 MiB.
parser_slice_size: T.Optional[int] = None  # 15 MiB.

# For ensuring that standard error writes are not interleaved, as multiple
# processes write debug information and logs to it.
STDERR_LOCK = mp.Lock()

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

sensor_addresses: T.Set[str] = set(("200.19.107.238",))

# Classes.


@dataclasses.dataclass(order=True)
class AttackTrack:
    observed_first: dt.datetime
    observed_last: dt.datetime
    bytes: int
    packets: int
    sensors: T.Set[str]


@dataclasses.dataclass(order=True)
class Attack:
    observed_first: dt.datetime
    observed_last: T.Optional[dt.datetime]
    bytes: int
    packets: int
    amplification_port: T.Union[int, str]
    victim: str
    sensors: T.Set[str]


@dataclasses.dataclass(order=True)
class AttackWindow:
    start: dt.datetime  # Inclusive.
    attacks: T.List[Attack]


# Helper functions.


def datetime_to_microseconds(datetime: dt.datetime) -> int:
    return int(datetime.timestamp() * 1_000_000) + datetime.microsecond


def microseconds_to_datetime(
    microseconds: int, timezone=dt.timezone.utc
) -> dt.datetime:
    return dt.datetime.fromtimestamp(
        microseconds / 1_000_000, tz=timezone
    ).replace(microsecond=microseconds % 1_000_000)


# Worker functions.

#Takes in four arguments: start datetime, end datetime, attack, timeout, line tuples
def worker_parser(
    start: dt.datetime,  # Inclusive.
    end: dt.datetime,  # Exclusive.
    attack_timeout: dt.timedelta,  # Inclusive.
    lines: T.Tuple[str, ...],
) -> T.Optional[AttackWindow]:
    tracked: T.Dict[
        T.Tuple[
            str,  # Source (spoofed) IP address observed.
            T.Union[int, str],  # Destination port observed (MP-H protocol).
        ],
        AttackTrack,
    ] = {}

    # NOTE: Minimum packet count filter happens at the end, not here. These are
    # only potential attacks.
    finished: T.List[Attack] = []

    first_timestamp: T.Optional[dt.datetime] = None
    for line in lines:
        #skips comments
        if not line or line[0] == "#":
            continue

        columns = line.split("|")
        #check if the timeout has been reached
        timestamp = microseconds_to_datetime(int(columns[0]))
        if start > timestamp:
            continue
        if end <= timestamp:
            # The files should be sorted by default, so exit early.
            break

        if first_timestamp is None:
            first_timestamp = timestamp
        #if protocol isn't chargen?
        if columns[1] != "17":
            continue

        #if the destination address isn't the honeypot address?
        destination_address = columns[4]
        if destination_address not in sensor_addresses:
            continue
        
        #checks if the amplifier was the honeypot
        source_address = columns[2]
        if source_address in sensor_addresses:
            continue
        
        destination_port: T.Union[int, str]
        destination_port = int(columns[5])
        if destination_port not in PROTOCOL_NAMES:
            continue
        destination_port = PROTOCOL_NAMES[destination_port]

        byte_count = int(columns[6])
        #if the packet is not part of currently collected attack, track it
        attack_pair = (os.path.splitext(source_address)[0], destination_port)
        if attack_pair not in tracked:
            tracked[attack_pair] = AttackTrack(
                timestamp,
                timestamp,
                byte_count,
                1,
                set((destination_address,)),
            )
        else:
            attack_track = tracked[attack_pair]
            if __debug__:
                # Files are sorted.
                if attack_track.observed_last > timestamp:
                    with STDERR_LOCK:
                        debug_timestamp = datetime_to_microseconds(timestamp)
                        debug_observed_last = datetime_to_microseconds(
                            attack_track.observed_last
                        )
                        print(
                            "WARNING: Unsorted timestamps -",
                            f" Current={debug_timestamp}"
                            f" <= Past={debug_observed_last}",
                            file=sys.stderr,
                        )
            #always updates the timestap, byte size, packet and sensors
            attack_track.observed_last = timestamp
            attack_track.bytes += byte_count
            attack_track.packets += 1
            attack_track.sensors.add(destination_address)

        for attack_pair, attack_track in tuple(tracked.items()):  # Collection.
            if timestamp - attack_track.observed_last > attack_timeout:
                finished.append(
                    Attack(
                        victim=attack_pair[0],
                        observed_first=attack_track.observed_first,
                        observed_last=attack_track.observed_last,
                        amplification_port=attack_pair[1],
                        bytes=attack_track.bytes,
                        packets=attack_track.packets,
                        sensors=attack_track.sensors,
                    )
                )
                del tracked[attack_pair]

    # These are not confirmed to be finished (in the sense of timing out), but
    # the merge will make sure of that later.
    while tracked:
        attack_pair, attack_track = tracked.popitem()
        finished.append(
            Attack(
                victim=attack_pair[0],
                observed_first=attack_track.observed_first,
                observed_last=None,  # See above comment.
                amplification_port=attack_pair[1],
                bytes=attack_track.bytes,
                packets=attack_track.packets,
                sensors=attack_track.sensors,
            )
        )

    if first_timestamp is None or not finished:
        return None

    finished.sort(key=lambda x: x.observed_first)
    return AttackWindow(first_timestamp, finished)

#Accepts start, end, attack timeout, window_start and file_path
def worker_counter(
    start: dt.datetime,  # Inclusive.
    end: dt.datetime,  # Exclusive.
    attack_timeout: dt.timedelta,  # Inclusive.
    window_start: dt.datetime,
    file_path: str,
) -> T.Tuple[AttackWindow, ...]:
    def log(message: str):
        with STDERR_LOCK:
            print(
                f"{window_start}@{dt.datetime.now()}: {message}",
                file=sys.stderr,
            )

    line_slices: T.List[T.Tuple[str, ...]] = []

    with gzip.open(file_path, "rt") as file:
        log(f"Reading '{file_path}' into memory...")
        while True:
            #only stores slices of default 15MiB
            lines = file.readlines(parser_slice_size or -1)
            if not lines:
                break
            # TODO: This contains a workaround for the unsorted timestamps.
            line_slices.append(
                tuple(
                    sorted(
                        (
                            line
                            for line in (
                                line.rstrip()
                                for line in lines
                                if line[0] != "#"
                            )
                            if line
                        ),
                        key=lambda x: int(x.split("|", maxsplit=2)[0]),
                    )
                )
            )

    log(
        f"Processing {len(line_slices)} line slices "
        f"({sum(len(lines) for lines in line_slices)} lines total)..."
    )
    #create a list that contains attack window
    windows: T.List[AttackWindow] = []
    if len(line_slices) > 1:
        #starts multi threading if there is more than one line slice
        with mp.Pool(min(len(line_slices), os.cpu_count() or 4)) as pool:
            #starts parallel programming
            for window in pool.starmap(
                worker_parser,
                (
                    (start, end, attack_timeout, line_slice)
                    for line_slice in line_slices
                ),
            ):
                if window is not None:
                    windows.append(window)
            # In case the rows aren't initially ordered.
            windows.sort(key=lambda x: x.start)
    elif line_slices:
        single_window = worker_parser(
            start, end, attack_timeout, line_slices.pop()
        )
        if single_window is not None:
            windows.append(single_window)

    log("Finished.")
    return tuple(windows)

#Responsible for carpet bomb/multiprotocol attack
#does it have to be?
def worker_merger(
    attack_timeout: dt.timedelta,
    low: AttackWindow,
    high: AttackWindow,
) -> AttackWindow:
    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Merging {low.start} with {high.start}",
            f"({len(low.attacks):,} and {len(high.attacks):,} attacks)...",
            file=sys.stderr,
        )
        if __debug__:
            if not low.start <= high.start:
                raise AssertionError(
                    f"Low start {low.start} is not lower "
                    f"than high start {high.start}"
                )

    window = AttackWindow(low.start, low.attacks + high.attacks)
    window.attacks.sort(key=lambda x: x.observed_first)  # Just to be sure.
    #checks if the data is "finished" or not
    #if the attack is not finished, then the attack is "merged"
    for index, attack in enumerate(window.attacks):
        if attack.observed_last is not None:
            continue
        future_index = index + 1
        while future_index < len(window.attacks):
            future_attack = window.attacks[future_index]
            #Checks if an attack is done or not.
            if (
                future_attack.observed_first - attack.observed_first
                > attack_timeout
            ):
                window.attacks[index] = dataclasses.replace(  # It's finished.
                    attack, observed_last=future_attack.observed_first
                )
                break
            #this may count for pulse wave attacks as well?
            if (
                future_attack.victim == attack.victim
                and future_attack.amplification_port
                == attack.amplification_port
            ):
                # This "extends the attack", and it may potentially finish it.
                window.attacks[index] = dataclasses.replace(
                    attack,
                    observed_last=future_attack.observed_last,
                    bytes=attack.bytes + future_attack.bytes,
                    packets=attack.packets + future_attack.packets,
                    sensors=attack.sensors.union(future_attack.sensors),
                )
                del window.attacks[future_index]

            future_index += 1

    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Resolving overlapped attacks "
            f"for {low.start} to {high.start}...",
            file=sys.stderr,
        )

    resort = False
    #so attack windows have observed last values but it's not always automatically set?
    #does it only set the attack observed last if the attack is finished?
    for index, attack in enumerate(window.attacks):
        if attack.observed_last is None:
            continue
        overlap_index = index + 1
        while overlap_index < len(window.attacks):
            overlap_attack = window.attacks[overlap_index]
            if overlap_attack.observed_first > attack.observed_last:
                break  # Save time.

            if (
                overlap_attack.victim == attack.victim
                and overlap_attack.amplification_port
                == attack.amplification_port
                and (
                    overlap_attack.observed_last is None
                    # The overlap detection.
                    or max(
                        attack.observed_first, overlap_attack.observed_first
                    )
                    < min(attack.observed_last, overlap_attack.observed_last)
                )
            ):
                attack = Attack(
                    observed_first=min(
                        attack.observed_first,
                        overlap_attack.observed_first,
                    ),
                    observed_last=(
                        max(attack.observed_last, overlap_attack.observed_last)
                        if overlap_attack.observed_last is not None
                        else None
                    ),
                    victim=attack.victim,
                    amplification_port=attack.amplification_port,
                    bytes=attack.bytes + overlap_attack.bytes,
                    packets=attack.packets + overlap_attack.packets,
                    #removes duplicates compared to attack.sensors + overlap_attack.sensors
                    sensors=attack.sensors.union(overlap_attack.sensors),
                )

                window.attacks[index] = attack
                del window.attacks[overlap_index]
                resort = True
                if attack.observed_last is None:
                    break
            else:
                overlap_index += 1

    if resort:
        with STDERR_LOCK:
            print(
                f"{dt.datetime.now()}: Overlapped attacks found and resolved "
                f"in {low.start} to {high.start}...",
                file=sys.stderr,
            )
        window.attacks.sort(key=lambda x: x.observed_first)

    return window


def main() -> int:
    argparser = argparse.ArgumentParser(
        description="""
        Processes attack counts for the MP-H PSV files (New Kids version).
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    argparser.add_argument(
        "-s",
        type=dt.datetime.fromisoformat,
        default=dt.datetime.fromtimestamp(0, tz=dt.timezone.utc),
        help="""
        Start datetime for the PSV files. ISO 8601 format. Inclusive.
        """,
    )

    argparser.add_argument(
        "-e",
        type=dt.datetime.fromisoformat,
        default=dt.datetime.fromtimestamp(2**31 - 1, tz=dt.timezone.utc),
        help="""
        End datetime for the PSV files. ISO 8601 format. Exclusive.
        """,
    )

    argparser.add_argument(
        "files",
        nargs="*",
        help="""
        PSV files to process directly. Ideally, avoid this and use the `-s` and
        `-e` flags instead. When the files are specified, the `-s` and `-e`
        arguments have no effect.
        """,
    )

    argparser.add_argument(
        "-t",
        type=float,
        default=60.0,  # Same as the MP-H paper.
        help="""
        Specifies when a tracked attack is considered finished if another
        spoofed request was not observed for that IP address in this amount of
        specified time. This is specified in seconds (decimals allowed).
        Microsecond precision can be given and is internally used. Inclusive.
        """,
    )

    argparser.add_argument(
        "--use-seconds-per-window",
        action="store_true",
        help="""
        When specified, the timestamps are outputted as seconds instead of
        microseconds.
        """,
    )

    argparser.add_argument(
        "--minimum-packets",
        type=int,
        default=5,  # Same as the MP-H paper.
        help="""
        Specifies how many spoofed packets must be received before a potential
        attack is considered an actual attack instead of a scanner; thus,
        appearing in the output of this tool. Inclusive.
        """,
    )

    argparser.add_argument(
        "--workers",
        type=int,
        default=os.cpu_count() or 8,
        help="""
        Specifies how many workers to use for the process pools. Defaults to
        the number of cores if detected. A worker count below 2 disables
        multiprocessing.
        """,
    )

    argparser.add_argument(
        "--sensor-addresses",
        type=str,
        default="",
        help="""
        A comma-separated list of the sensor addresses to consider as honeypot
        sensors.
        """,
    )

    argparser.add_argument(
        "--no-command-line-arguments-comment",
        action="store_true",
        help="""
        When specified, the command line arguments are not included in the
        output after the initial header.
        """,
    )
    #seems to read every files in a folder
    argparser.add_argument(
        "--base-directory",
        type=str,
        default="/Scratch/rs266/MP-H/",
        help="""
        The path to the top directory of the MP-H PSV files. Ignored if files
        are passed directly.
        """,
    )

    argv = argparser.parse_args()
    #The start time of what to collect
    start: dt.datetime = (
        argv.s.replace(tzinfo=dt.timezone.utc)
        if argv.s.tzinfo is None
        else argv.s
    )
    #The end time of what to collect
    end: dt.datetime = (
        argv.e.replace(tzinfo=dt.timezone.utc)
        if argv.e.tzinfo is None
        else argv.e
    )
    
    attack_timeout = dt.timedelta(seconds=max(argv.t, 0.0))
    #minimum packet to be counted as an attack?
    minimum_packets: int = max(argv.minimum_packets, 1)
    #the amount of processors that will be used
    workers: int = argv.workers
    #??
    use_seconds_per_window: bool = argv.use_seconds_per_window
    #the base directory the file will use
    base_directory: str = argv.base_directory

    no_command_line_arguments_comment: bool = (
        argv.no_command_line_arguments_comment
    )
    #The addresses to be considered
    if argv.sensor_addresses:
        sensor_addresses.clear()
        for address in argv.sensor_addresses.split(","):
            try:
                sensor_addresses.add(str(ip.ip_address(address.strip())))
            except ValueError:
                print(
                    f"Invalid sensor IP address: '{address}'.",
                    file=sys.stderr,
                )
                return 1

    if not sensor_addresses:
        print("No sensor IP addresses were specified.", file=sys.stderr)
        return 1
    #Checks if file of a certain time exists
    def file_datetime_parser(file_path: str) -> T.Optional[dt.datetime]:
        if not os.path.isfile(file_path):
            print(
                f"File does not exist: '{file_path}'. Skipping...",
                file=sys.stderr,
            )
            return None

        try:
            return dt.datetime.strptime(
                os.path.basename(file_path), "%Y-%m-%dT%H:%M:%SZ.gz"
            ).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            print(
                f"Base filename is misnamed: '{file_path}'. Skipping...",
                file=sys.stderr,
            )
            return None
    #If there is no specified timestamp, it goes through a folder and keeps calling file_datetime_parser
    #else if a file path is given, it only calls this file
    files: T.Dict[dt.datetime, str] = {}
    if not argv.files:
        for file_path in glob.iglob(
            base_directory + "/**/*.gz", recursive=True
        ):
            file_datetime = file_datetime_parser(file_path)
            if file_datetime is not None and start <= file_datetime < end:
                files[file_datetime] = file_path
    else:
        for file_path in argv.files:
            file_datetime = file_datetime_parser(file_path)
            if file_datetime is not None:
                files[file_datetime] = file_path
        if files:
            start = min(files)  # We can still set this to the earliest file.

    if not files:
        print("No files found.", file=sys.stderr)
        return 1
    #Spawns multiple workers
    if workers > 1:
        with CustomPool(workers) as pool:
            counted = [
                window
                for windows in pool.starmap(
                    worker_counter,
                    (
                        (
                            start,
                            end,
                            attack_timeout,
                            file_date,
                            files[file_date],
                        )
                        for file_date in sorted(files)
                    ),
                )
                for window in windows
                if window is not None
            ]

            results = cll.deque(
                maxlen=len(counted),
                iterable=sorted(
                    (counted.pop() for _ in range(len(counted))),
                    key=lambda x: x.start,
                ),
            )

            while len(results) > 1:
                with STDERR_LOCK:
                    print(
                        f"{dt.datetime.now()}: "
                        f"Merging {len(results):,} results...",
                        file=sys.stderr,
                    )

                # Take the two windows next to each other, merge them, then add
                # the result back to the start. This can be done concurrently
                # by merging multiple pairs.
                results.extendleft(
                    sorted(
                        pool.starmap(
                            worker_merger,
                            (
                                (
                                    attack_timeout,
                                    results.popleft(),
                                    results.popleft(),
                                )
                                for _ in range(len(results) // 2)
                            ),
                        ),
                        key=lambda x: x.start,
                        reverse=True,  # `extendleft` also reverses the order.
                    )
                )
    else:
        global parser_slice_size
        parser_slice_size = None

        counted = [
            window
            for file_date in sorted(files)
            for window in worker_counter(
                start,
                end,
                attack_timeout,
                file_date,
                files[file_date],
            )
            if window is not None
        ]

        results = cll.deque(
            maxlen=len(counted),
            iterable=sorted(
                (counted.pop() for _ in range(len(counted))),
                key=lambda x: x.start,
            ),
        )

        while len(results) > 1:
            print(
                f"{dt.datetime.now()}: Merging {len(results):,} results...",
                file=sys.stderr,
            )
            results.append(
                worker_merger(
                    attack_timeout, results.popleft(), results.popleft()
                )
            )

    if results:
        result = results.pop()
        assert not results
        with STDERR_LOCK:
            print("Outputting results...", file=sys.stderr)
    else:
        result = AttackWindow(start, [])
        with STDERR_LOCK:
            print(
                "No results. Still outputting comment rows...", file=sys.stderr
            )

    attacks = tuple(
        filter(lambda x: x.packets >= minimum_packets, result.attacks)
    )
    del result

    if attacks:
        final_attack = attacks[-1]
        if final_attack.observed_last is not None:
            final_observation = final_attack.observed_last
        else:
            final_observation = final_attack.observed_first
    else:
        final_observation = end  # Just to silence an unbound warning.

    def timestamper(datetime: dt.datetime) -> int:
        if use_seconds_per_window:
            return int(datetime.timestamp())
        return datetime_to_microseconds(datetime)

    print(
        "# start",
        "end",
        "victim",
        "amp_proto",
        "bytes",
        "pkts",
        "sensors",
        sep="|",
    )

    print(
        (
            "# first_observation_timestamp_"
            f"{'micro' if not use_seconds_per_window else ''}seconds_utc"
        ),
        (
            "last_observation_timestamp_"
            f"{'micro' if not use_seconds_per_window else ''}seconds_utc"
        ),
        "victim_address",
        "amplification_protocol_or_port",
        "total_byte_count",
        "total_packet_count",
        "total_sensor_contact_count",
        sep="|",
    )

    if not no_command_line_arguments_comment:
        print("#", " ".join(sys.argv))

    for attack in attacks:
        # The script is fast enough that we can just do this here.
        if attack.packets < minimum_packets:
            continue

        if __debug__:
            if attack.observed_last is not None:
                assert attack.observed_first <= attack.observed_last

        # TODO: What behaviour do we want for attacks that are still ongoing
        # (i.e., haven't timed out) after the end given by the user? For now,
        # I'll just use the final timestamp observed and append "+" to the
        # start of it. Shouldn't break integer parsers (good ones at least).
        # Ignored when files were explicitly passed.
        if attack.observed_last is None:
            observed_last = f"+{timestamper(final_observation)}"
        else:
            observed_last = str(timestamper(attack.observed_last))

        print(
            timestamper(attack.observed_first),
            observed_last,
            attack.victim,
            attack.amplification_port,
            attack.bytes,
            attack.packets,
            len(attack.sensors),
            sep="|",
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
