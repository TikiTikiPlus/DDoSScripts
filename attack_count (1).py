#!/usr/bin/env python3
__author__ = "RavSS"

import argparse
import collections as cll
import dataclasses
import datetime as dt
import glob
import gzip
import ipaddress as ip  # Rav: Overall avoid this, as strings are good enough.
import multiprocessing as mp
import multiprocessing.pool as mp_pool
import os
import sys
import typing as T

# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
# Notes:
# Code uses parallel programming through starmap
# One feature the code uses to prevent overflows is the the max parser slice size.
# When the readlines function reaches the max parser slice size, code moves to line_slice append.
# line slice appends the lines that was received from readlines.
# The reason why this works is that it uses a list of lists.
# Because lists have a limit of 65535 elements, the code doesn't crash.
# Line_slice only contains pointers to other lists.
# Code also uses Tuples which are more efficient than lists as instead fo looping through lists to get what is wanted,
# tuples have keys which makes it easier to grab what the coder wants based on the keys specified.
# Using T.union will be helpful in terms of counting sensor addresses. Especially if we dont know the sensor addresses.
# May also be helpful in terms of counting the victims of multiprotocol attacks and list the protocols that was included in the attacks.
# Sys.stderr is useful in consistent messaging compared to print
# another way it saves memory is deleting attack pairs that have already been tagged as finished in the list
# Code uses async results
# also uses tracker arguments for the different attack classifications.
# because they all have the same arguments, *tracker_arguments can be used for readability.
# Uses enumerate to make it easier to keep track of the indices
# uses print(,) and separator "|" to print contents as it is more efficient.
# using deque allows for fast operations.
# also required when running in programs in parallel as dequeing allows for adding and removing elements without corrupting the tuple or list
# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------

# ------------------------------------ Rav ------------------------------------
# - Overflows regarding lists are not possible here. CPython's `list`
# essentially has no limit, or at least is up to the limit of whatever
# `ssize_t` is, i.e. almost limited by the platform's memory limit.
# - Tuples don't use keys, but rather numeric indices. They might have
# attributes if named tuples are being used.
# - The "T." annotations are only for type hints; they have no impact on
# runtime behaviour. You can ignore them entirely since they can look like
# clutter at times, but it helps static type checkers like mypy.
# - Using `sys.stderr` with `print()` is not too different from using
# `print()` without it (implicit `sys.stdout`). It's only for logging
# purposes, and we create a lock to make sure that only one process outputs to
# the standard error stream at a time. The actual output goes to the standard
# output stream, so we don't want to mix them up.
# ------------------------------------ Rav ------------------------------------


# Rav: This is a hack to make the default multiprocessing pool not spawn daemon
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


# Responsible for creating a nodaemon process
# NoDaemon process makes programs still run even if the program closes - Ralph
class CustomPool(mp_pool.Pool):
    def Process(self, *args, **kwargs):
        proc = super().Process(*args, **kwargs)  # type: ignore
        proc.__class__ = NoDaemonProcess
        return proc


# Globals

# Rav: Splits a file into a (roughly) sized slice so we waste less time using a
# single core on a massive file, as files may vary heavily in length. The pool
# hack was for this. If this is too low, then a fork bomb essentially occurs.
# Set this to `None` to disable it.
parser_slice_size: T.Optional[int] = 15 * 2**20  # 15 MiB.

# Rav: For ensuring that standard error writes are not interleaved, as multiple
# processes write debug information and logs to it.
STDERR_LOCK = mp.Lock()

PROTOCOL_NAMES = {  # Rav: Some of the service/protocol names recognised here.
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

# Rav: Only packets headed towards these addresses are considered.
sensor_addresses: T.Set[str] = set(
    f"200.19.107.{i}" for i in range(1, 255 + 1)
)

# Classes.


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
# dataclasses are used as it generates constructor, repr and eq
# dataclasses also makes the code cleaner and have less garbage code
# using set will mke the code easier to grab values.
# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
@dataclasses.dataclass(order=True)
class AttackTrack:
    observed_first: dt.datetime
    observed_last: dt.datetime
    bytes: int
    packets: int
    sensors: T.Set[str]


# Rav: `AttackTrack` and `Attack` are similar, but the former just has some
# fields omitted for space-saving purposes.
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


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
# responsible for attack counting
# has attackwindow object and attacktrack object
# attackwindow is responsible for start time of log files and list of finished attacks
# attacktrack object tracks attacks that are not yet finished.

# The function processes a list of lines, which are in ISO8601 time.
# It first initializes an empty dictionary called tracked, which will be used to keep track of ongoing attacks.
# It also initializes an empty list called finished, which will be used to store finished attacks.

# The function extracts the timestamp from the first column of the line and checks if it falls within the time window specified by start and end. I
# if the timestamp is outside this window, the function skips to the next line.

# The function then extracts the source IP address and destination port from the line. If the source address is in the set of sensor addresses,
# the function skips to the next line.

# If the destination port is a protocol number recognized by the program, the function converts the protocol number to its corresponding protocol name.

# The function then extracts the byte count from the line and creates a tuple called attack_pair consisting of the source IP address and the
# destination port.

# If attack_pair is not already in the tracked dictionary, the function adds it to the dictionary with a new AttackTrack object as its value.
# If attack_pair is already in the dictionary, the function updates the existing AttackTrack object with the new timestamp and byte count.

# The function then iterates through the tracked dictionary and checks if any of the ongoing attacks have timed out
# (i.e., the time since the last observed packet exceeds attack_timeout). If an attack has timed out,
# the function creates a new Attack object for the finished attack and appends it to the finished list.
# The function then removes the finished attack from the tracked dictionary.

# After processing all the lines, the function checks if any finished attacks were found and returns an AttackWindow
# object containing the earliest timestamp of the processed lines and the list of finished attacks.
# If no finished attacks were found, the function returns None.
# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------


def attack_counter(
    start: dt.datetime,  # Rav: Inclusive.
    end: dt.datetime,  # Rav: Exclusive.
    attack_timeout: dt.timedelta,  # Rav: Inclusive.
    lines: T.Tuple[str, ...],
) -> T.Optional[AttackWindow]:
    tracked: T.Dict[
        T.Tuple[
            str,  # Rav: Source (spoofed) IP address observed.
            # Rav: Destination port observed (MP-H protocol).
            T.Union[int, str],
        ],
        AttackTrack,
    ] = {}

    # NOTE: Rav: Minimum packet count filter happens at the end, not here.
    # These are only potential attacks.
    finished: T.List[Attack] = []

    first_timestamp: T.Optional[dt.datetime] = None
    for line in lines:
        if not line or line[0] == "#":  # Rav: Skip empty/comment lines.
            continue

        columns = line.split("|")

        timestamp = microseconds_to_datetime(int(columns[0]))
        if start > timestamp:
            continue
        if end <= timestamp:
            # Rav: The files should be sorted by default, so exit early.
            break

        if first_timestamp is None:
            first_timestamp = timestamp

        if columns[1] != "17":  # Rav: Must be UDP.
            continue

        destination_address = columns[4]
        if destination_address not in sensor_addresses:
            continue

        source_address = columns[2]
        if source_address in sensor_addresses:
            continue

        destination_port: T.Union[int, str]
        destination_port = int(columns[5])
        if destination_port in PROTOCOL_NAMES:
            destination_port = PROTOCOL_NAMES[destination_port]

        byte_count = int(columns[6])
        # creates tuple attack pair - Ralph
        attack_pair = (source_address, destination_port)
        if attack_pair not in tracked:
            tracked[attack_pair] = AttackTrack(
                timestamp,
                timestamp,
                int(byte_count),
                1,
                set((destination_address,)),
            )
        else:
            attack_track = tracked[attack_pair]
            # Rav: This check will be removed if Python is run with the -O
            # flag.
            if __debug__:
                # Files are sorted. - Ralph
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
            attack_track.observed_last = timestamp
            attack_track.bytes += int(byte_count)
            attack_track.packets += 1
            attack_track.sensors.add(destination_address)

        for attack_pair, attack_track in tuple(tracked.items()):
            # if the attack is finished, delete the attack pair to be tracked to save time. - Ralph
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

    # Rav: These are not confirmed to be finished (in the sense of timing out), but
    # the merge will make sure of that later.
    while tracked:
        attack_pair, attack_track = tracked.popitem()
        finished.append(
            Attack(
                victim=attack_pair[0],
                observed_first=attack_track.observed_first,
                observed_last=None,  # Rav: See above comment.
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


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------

# Chops down the log file further to work in parallel
# once all the workers are finished, they are all merged into one file
# It divides the log data into smaller chunks and then processes them by calling the attack_counter function.
# The resulting AttackWindow objects returned by attack_counter are added to the windows list, which is then sorted by the time the attack has
# started. If the attack_counter function returns a window of attack, the single window is added to the windows list.
# Finally, the function returns a tuple of all the AttackWindow objects that were processed.

# The log function is a nested function that simply prints messages to the standard error stream with a timestamp.
# This function is used to log progress and errors.

# The line_slices variable is a list of tuples, where each tuple contains the lines from a slice of the log file.
# The gzip module is used to read the compressed log file. Each slice is generated using the readlines() method,
# which reads the specified number of lines, the default being 15MiB, or reads the entire file if -1 is passed as the argument.

# The min() function is used to determine the number of processes to create in the multiprocessing pool.
# The number of processes created is the minimum of the number of slices and the number of CPU cores on the machine.

# The AttackWindow objects returned by attack_counter are added to the windows list and sorted by the start time of the attack.
# The sorted list of windows is then returned as a tuple.

# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------


def worker_counter(
    start: dt.datetime,  # Rav: Inclusive.
    end: dt.datetime,  # Rav: Exclusive.
    attack_timeout: dt.timedelta,  # Rav: Inclusive.
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
    # limits the size of lines - Ralph
    with gzip.open(file_path, "rt") as file:
        log(f"Reading '{file_path}' into memory...")
        while True:
            lines = file.readlines(parser_slice_size or -1)
            if not lines:
                break
            # TODO: Rav: This contains a workaround for the unsorted
            # timestamps. Comes with a performance penalty, as we have to
            # minimally parse and sort the lines.
            line_slices.append(
                tuple(
                    sorted(
                        (
                            line
                            for line in (line.strip() for line in lines)
                            if line and line[0] != "#"
                        ),
                        key=lambda x: int(x.split("|", maxsplit=2)[0]),
                    )
                )
            )

    log(
        f"Processing {len(line_slices)} line slices "
        f"({sum(len(lines) for lines in line_slices)} lines total)..."
    )
    windows: T.List[AttackWindow] = []
    # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
    # divides the log data into smaller chunks
    # the objects returned by worker parser are added to the windows list
    # then sorted by the time the attack has started
    # if the attack_counter returns a window of attack,
    # the single window is added to the windows list
    # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
    if len(line_slices) > 1:
        with mp.Pool(min(len(line_slices), os.cpu_count() or 4)) as pool:
            for window in pool.starmap(
                attack_counter,
                (
                    (start, end, attack_timeout, line_slice)
                    for line_slice in line_slices
                ),
            ):
                if window is not None:
                    windows.append(window)
            # Rav: In case the rows aren't initially ordered.
            windows.sort(key=lambda x: x.start)
    elif line_slices:
        single_window = attack_counter(
            start, end, attack_timeout, line_slices.pop()
        )
        if single_window is not None:
            windows.append(single_window)

    log("Finished.")
    return tuple(windows)


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------

# This is a Python function that takes in two AttackWindow objects (low and high) and merges them into a single AttackWindow object.

#     attack_timeout: represents the maximum amount of time that an attack lasts before it is considered finished
#     low: an AttackWindow object representing the lower half of the time window to be merged
#     high: an AttackWindow object representing the upper half of the time window to be merged

# The function returns an AttackWindow object that represents the merged time window.

# The function then loops through each attack in the merged window.
# If an attack has an observed_last attribute, it is considered finished and the function moves on to the next attack.
# Otherwise, it looks at the next attack in the list and checks if it is part of the same attack as the current one
# (i.e., if it has the same victim and amplification_port attributes).
# If it is, the function extends the current attack by adding the bytes, packets, and sensors from the next attack to the current one.
# If the time between the observed_first attribute of the current attack and the next attack is greater than the attack_timeout,
# the current attack is considered finished. If the next attack extends the current attack, the next attack is removed from the list.

# After merging attacks that belong together, worker merger looks for overlapping attacks.
# It loops through each attack in the merged window again, but this time looking for attacks that overlap with the current attack.
# If an attack overlaps with the current one, the function merges the two attacks into a single attack.
# If the merged attack has an observed_last attribute, the function removes the overlapping attack from the list.
# If any overlapping attacks were merged, the function sorts the attacks again.

# Finally, the function returns the merged AttackWindow object.


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
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
    # Rav: Sort it just to be sure.
    window.attacks.sort(key=lambda x: x.observed_first)

    for index, attack in enumerate(window.attacks):
        if attack.observed_last is not None:
            continue
        future_index = index + 1
        while future_index < len(window.attacks):
            future_attack = window.attacks[future_index]

            if (
                future_attack.observed_first - attack.observed_first
                > attack_timeout
            ):
                # Rav: The attack has been finished.
                window.attacks[index] = dataclasses.replace(
                    attack, observed_last=future_attack.observed_first
                )
                break

            if (
                future_attack.victim == attack.victim
                and future_attack.amplification_port
                == attack.amplification_port
            ):
                # Rav: This "extends the attack", and it may potentially finish
                # it.
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
    for index, attack in enumerate(window.attacks):
        if attack.observed_last is None:
            continue
        overlap_index = index + 1
        while overlap_index < len(window.attacks):
            overlap_attack = window.attacks[overlap_index]
            if overlap_attack.observed_first > attack.observed_last:
                break  # Rav: Save time by exiting early.

            if (
                overlap_attack.victim == attack.victim
                and overlap_attack.amplification_port
                == attack.amplification_port
                and (
                    overlap_attack.observed_last is None
                    # Rav: The overlap detection.
                    or max(
                        attack.observed_first, overlap_attack.observed_first
                    )
                    < min(attack.observed_last, overlap_attack.observed_last)
                )
            ):  # when merging to attacks, the attacks
                # check the lesser value to be replaced in the observed first
                # - Ralph
                attack = Attack(
                    observed_first=min(
                        attack.observed_first,
                        overlap_attack.observed_first,
                    ),
                    # the observed time will be assigned to whichever attack has the higher value - Ralph
                    observed_last=(
                        max(attack.observed_last, overlap_attack.observed_last)
                        if overlap_attack.observed_last is not None
                        else None
                    ),
                    victim=attack.victim,
                    amplification_port=attack.amplification_port,
                    bytes=attack.bytes + overlap_attack.bytes,
                    packets=attack.packets + overlap_attack.packets,
                    # when union is called, checks for any separate sensors not stored before - Ralph
                    # Rav: It's equivalent to doing
                    #      `attack.sensors | overlap_attack.sensors`
                    #      The style below is a little older.
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


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
# tracks multi-protocol attacks.
# It takes as input a tuple of Attack objects and a timeout period, and returns a tuple of identities and counts.

# For each attack, the function checks if it has already been assigned an identity.
# If so, the function appends the count of the corresponding multi-protocol attack to the counts list and moves on to the next attack.
# Otherwise, it generates a new identity for the multi-protocol attack and adds it to the identities dictionary.

# The function then enters another loop that iterates over all subsequent attacks in the input tuple.
# For each attack, the function checks if it occurred within the timeout period of the previous attack
# and has the same victim as the previous attack.
# If so, the function checks if the attack was performed on a different port than the previous attack, and if so,
# it assigns the same identity as the previous attack and updates the observed_last time.

# The function continues iterating over subsequent attacks until either the timeout period has elapsed or
# no more attacks meet the criteria for being part of the same multi-protocol attack.

# Finally, the function appends the count of the current multi-protocol attack to the counts list,
# and then returns the identities and counts as tuples.


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
def track_attack_multi_protocol(
    attacks: T.Tuple[Attack, ...],
    attack_timeout: dt.timedelta,
) -> T.Tuple[T.Tuple[str, ...], T.Tuple[int, ...]]:
    identity = 1
    identities: T.Dict[int, str] = {}

    count = 0
    counts: T.List[int] = []

    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Multi-protocol",
            "attacks are being tracked...",
            file=sys.stderr,
        )

    # how the program assigns identities is through the use of checking every future indices before exiting - Ralph
    for index, attack in enumerate(attacks):
        # makes the identity not overwrite its previous identifier - Ralph
        if index in identities:
            counts.append(count)
            continue
        # identity is turned into their hex values - Ralph
        current_identity = (
            f"MP_0x{int(attack.observed_first.timestamp()):X}${identity}"
        )
        identities[index] = current_identity
        identity += 1
        observed_last: T.Optional[dt.datetime] = attack.observed_last

        seen = False  # Rav: We need to see at least two different ports.

        future_index = index + 1
        while future_index < len(attacks):
            future_attack = attacks[future_index]
            if (
                observed_last is not None
                and future_attack.observed_first - observed_last
                > attack_timeout
            ):
                break

            if future_attack.victim == attack.victim and (
                seen
                or future_attack.amplification_port
                != attack.amplification_port
            ):
                # Rav: Now we've confirmed it's a multi-protocol attack, so we
                # don't need to check the port again and can keep extending it
                # until it times out.
                if not seen:
                    seen = True
                    count += 1
                identities[future_index] = current_identity
                if observed_last is not None and (
                    future_attack.observed_last is None
                    or future_attack.observed_last > observed_last
                ):
                    observed_last = future_attack.observed_last

            future_index += 1
        counts.append(count)

    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Multi-protocol",
            "attacks finished being tracked.",
            file=sys.stderr,
        )

    return tuple(identities[index] for index in sorted(identities)), tuple(
        counts
    )


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
# This function is used to track carpet bombing attacks in a given set of attacks.
# The function takes a tuple of `Attack` objects and an attack timeout duration as input, and returns two tuples as output.

# The first tuple contains unique identifiers for each carpet bombing attack,
# and the second tuple contains the number of attacks associated with each identifier.

# Inside the function, it initializes some variables and prints a message to the standard error stream indicating that carpet bombing
# attacks are being tracked. Then, it iterates through each attack in the input tuple, checking if it has already been assigned an identifier.
# If it has, it appends the count of attacks associated with that identifier to a list and continues to the next attack. Otherwise,
# it assigns a new identifier to the attack and checks for subsequent attacks that match the carpet bombing criteria
# (i.e., attacks that target multiple hosts within the same /24 prefix). It keeps extending the attack until timeout is reached or no
#  more attacks are found that match the criteria. It then adds the count of attacks associated with that identifier to a list and moves
# to the next unassigned attack.


# Finally, the function prints a message indicating that tracking of carpet bombing attacks has finished,
# and returns the two tuples containing the unique identifiers and associated attack counts.
# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
def track_attack_carpet_bombing(
    attacks: T.Tuple[Attack, ...],
    attack_timeout: dt.timedelta,
) -> T.Tuple[T.Tuple[str, ...], T.Tuple[int, ...]]:
    identity = 1
    identities: T.Dict[int, str] = {}

    count = 0
    counts: T.List[int] = []

    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Carpet bombing",
            "attacks are being tracked...",
            file=sys.stderr,
        )

    for index, attack in enumerate(attacks):
        if index in identities:
            counts.append(count)
            continue

        current_identity = (
            f"CB_0x{int(attack.observed_first.timestamp()):X}${identity}"
        )
        identities[index] = current_identity
        identity += 1
        observed_last: T.Optional[dt.datetime] = attack.observed_last

        # Rav: We need to see at least two different hosts from the same /24
        # prefix.
        seen = False

        # NOTE: This trick will only work on IPv4 addresses.
        # Possibly use delimiters next time if we are to collect non IPv4's - Ralph
        # Rav: To make this IPv6-compatible, I would recommend using the
        #      "ipaddress" module that is already imported as "ip".
        attack_prefix, _ = os.path.splitext(attack.victim)

        future_index = index + 1
        while future_index < len(attacks):
            future_attack = attacks[future_index]
            if (
                observed_last is not None
                and future_attack.observed_first - observed_last
                > attack_timeout
            ):
                break

            if (
                seen or future_attack.victim != attack.victim
            ) and os.path.splitext(future_attack.victim)[0] == attack_prefix:
                # Rav: Confirmed carpet bombing attack. We can keep
                # extending/counting it as long as we see one of the hosts
                # being attacked (even the original host).
                if not seen:
                    seen = True
                    count += 1
                identities[future_index] = current_identity
                if observed_last is not None and (
                    future_attack.observed_last is None
                    or future_attack.observed_last > observed_last
                ):
                    observed_last = future_attack.observed_last

            future_index += 1
        counts.append(count)

    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Carpet bombing",
            "attacks finished being tracked.",
            file=sys.stderr,
        )

    return tuple(identities[index] for index in sorted(identities)), tuple(
        counts
    )


# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
# This is a Python function that takes in a tuple of `Attack` objects and a timeout duration,
#  returns a tuple of identities and counts. The function tracks carpet bombing and multi-protocol attacks by
# identifying attacks that occur within the same /24 network prefix and have different ports,
# and then tracks those attacks until they either end or exceed the timeout duration.

# The identities are represented as strings that start with "CBMP" (for carpet bombing multi-protocol),
# followed by the hex value of the first observed timestamp of the attack, followed by a unique identifier.
# The counts represent the number of distinct carpet bombing multi-protocol attacks that were identified.

# The function first initializes an identity counter and a dictionary to store identities,
# and a count variable and a list to store counts. It then prints a message to stderr indicating that the tracking process has started.

# The function then iterates through the tuple of `Attack` objects, and for each attack, it checks whether it has already been assigned an
# identity. If it has, the function appends the previously calculated count to the counts list and moves on to the next attack.
# If it hasn't, the function calculates a new identity using the attack's observed first timestamp and the identity counter, adds
# the identity to the dictionary, and increments the identity counter.

# The function then initializes flags for tracking whether a carpet bombing and a multi-protocol
# attack have been seen for the current attack, as well as a flag for whether any attack has been seen.
# It then extracts the prefix (first three octets) of the victim's IP address and initializes a set to keep track of the
# indexes of attacks that may contribute to the current attack's identity.

# The function then enters a while loop that iterates through the remaining attacks in the tuple. For each future attack,
# the function checks whether it occurred within the timeout duration of the current attack. If it didn't, the function breaks
# out of the loop. If it did, the function checks whether the future attack occurred within the same /24 prefix as the current
# attack and whether it has a different port. If the future attack satisfies these conditions, the function updates the relevant
# flags and adds the future attack's index to the contributors set.

# If both a carpet bombing and a multi-protocol attack have been seen and the future attack also satisfies the /24 prefix condition,
# the function checks whether this is the first attack that satisfies these conditions. If it is, the function increments the count,
# assigns the current identity to all attacks in the contributors set, and updates the observed last timestamp of the current attack
# to the observed last timestamp of the future attack, if the future attack has a later observed last timestamp.
# If it isn't the first attack, the function simply assigns the current identity to the future attack and updates the observed
# last timestamp of the current attack if necessary.

# Once the while loop has finished iterating through all future attacks, the function appends the count to the counts list and moves
# on to the next attack in the original tuple.


# Finally, the function prints a message to stderr indicating that the tracking process has finished,
# and returns a tuple of identities and counts. The identities tuple is generated by sorting the keys of
# the identities dictionary and using them to look up the corresponding values, and the counts tuple is simply the counts list.
# ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
def track_attack_carpet_bombing_multi_protocol(
    attacks: T.Tuple[Attack, ...],
    attack_timeout: dt.timedelta,
) -> T.Tuple[T.Tuple[str, ...], T.Tuple[int, ...]]:
    identity = 1
    identities: T.Dict[int, str] = {}

    count = 0
    counts: T.List[int] = []

    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Carpet bombing multi-protocol",
            "attacks are being tracked...",
            file=sys.stderr,
        )

    for index, attack in enumerate(attacks):
        if index in identities:
            counts.append(count)
            continue

        current_identity = (
            f"CBMP_0x{int(attack.observed_first.timestamp()):X}${identity}"
        )
        identities[index] = current_identity
        identity += 1
        observed_last: T.Optional[dt.datetime] = attack.observed_last

        # Rav: We need to see at least two different hosts from the same /24
        # prefix and two different ports. Once we see that, we extend the
        # attack tracking until it times out, even we only see repeated hosts
        # and the same port until then.
        # NOTE: I've made it so it's easy to change between "and" or "or".
        seen_carpet_bombing = False
        seen_multi_protocol = False
        seen = False

        # NOTE: Rav: This trick will only work on IPv4 addresses.
        attack_prefix, _ = os.path.splitext(attack.victim)

        # Rav: Since we're tracking two things at once (of which a row can
        # contribute to only one of them), we need to keep track of indexes
        # until we can confirm that we've seen both.
        contributors: T.Set[int] = set()

        future_index = index + 1
        while future_index < len(attacks):
            future_attack = attacks[future_index]
            if (
                observed_last is not None
                and future_attack.observed_first - observed_last
                > attack_timeout
            ):
                break

            future_attack_prefix, _ = os.path.splitext(future_attack.victim)

            if not seen_carpet_bombing:
                seen_carpet_bombing = (
                    future_attack.victim != attack.victim
                    and future_attack_prefix == attack_prefix
                )
                if seen_carpet_bombing:
                    contributors.add(future_index)
            # if the ports are not the same but the prefixes are the same, the attack is carpet bombing - Ralph
            if not seen_multi_protocol:
                seen_multi_protocol = (
                    future_attack.amplification_port
                    != attack.amplification_port
                    and future_attack_prefix == attack_prefix
                )
                if seen_multi_protocol:
                    contributors.add(future_index)

            if (
                seen_carpet_bombing and seen_multi_protocol
            ) and future_attack_prefix == attack_prefix:
                if not seen:
                    seen = True
                    count += 1
                    for contributing_index in (
                        contributors.pop() for _ in range(len(contributors))
                    ):
                        identities[contributing_index] = current_identity
                else:
                    identities[future_index] = current_identity
                if observed_last is not None and (
                    future_attack.observed_last is None
                    or future_attack.observed_last > observed_last
                ):
                    observed_last = future_attack.observed_last

            future_index += 1
        counts.append(count)

    with STDERR_LOCK:
        print(
            f"{dt.datetime.now()}: Carpet bombing multi-protocol",
            "attacks finished being tracked.",
            file=sys.stderr,
        )

    return tuple(identities[index] for index in sorted(identities)), tuple(
        counts
    )


def main() -> int:
    argparser = argparse.ArgumentParser(
        description="Processes attack counts for the MP-H PSV files.",
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
        default=60.0,  # Rav: Same as the MP-H paper.
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
        default=5,  # Rav: Same as the MP-H paper.
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
        "--do-not-compute-attack-types",
        action="store_true",
        help="""
        When specified, three extra columns at the end will be omitted for
        multi-protocol attacks, carpet bombing attacks, and multi-protocol
        carpet bombing attacks, of which the value ("identity") refers to which
        attack instance the row belongs to.
        """,
    )

    argparser.add_argument(
        "--all-unique-attack-identities",
        action="store_true",
        help="""
        When specified, attack identities that are unique to a single row are
        kept in the output, even when such identities only identify which rows
        did not belong to an attack type and are thus noise.
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

    argparser.add_argument(
        "--base-directory",
        type=str,
        default="/Scratch/rs266/MP-H/",
        help="""
        The path to the top directory of the MP-H PSV files. Ignored if files
        are passed directly.
        """,
    )
    # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
    # The code starts by parsing command line arguments using the `argparse` module.
    # It sets variables for the start and end times to collect data for, an attack timeout, a minimum packet count,
    # the number of worker processes to use, and various other options.

    # It then uses a function called `file_datetime_parser` to parse the date and time from each file name in the specified directory
    # (or directories) that match the expected pattern `'%Y-%m-%dT%H:%M:%SZ.gz'`

    # If multiple worker processes are specified, it uses a custom pool of worker processes to count the number of packets in each window
    # of time for each file in the dictionary, then merges the results of each window of time using a parallel merge sort algorithm.

    # If only one worker process is specified, it uses the same process to count the packets and merge the results.
    # Finally, the code prints the result of the analysis.
    # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
    argv = argparser.parse_args()
    # start time we want to collect - Ralph
    start: dt.datetime = (
        argv.s.replace(tzinfo=dt.timezone.utc)
        if argv.s.tzinfo is None
        else argv.s
    )
    # end time of the data that wants to be collected - Ralph
    end: dt.datetime = (
        argv.e.replace(tzinfo=dt.timezone.utc)
        if argv.e.tzinfo is None
        else argv.e
    )
    # attack timeout - Ralph
    attack_timeout = dt.timedelta(seconds=max(argv.t, 0.0))
    # identification of how much packets is in an attack - Ralph
    minimum_packets: int = max(argv.minimum_packets, 1)
    # how many processors that we are using - Ralph
    workers: int = argv.workers
    # uses seconds instead of microseconds - Ralph
    use_seconds_per_window: bool = argv.use_seconds_per_window

    do_not_compute_attack_types: bool = argv.do_not_compute_attack_types
    all_unique_attack_identities: bool = argv.all_unique_attack_identities
    base_directory: str = argv.base_directory
    no_command_line_arguments_comment: bool = (
        argv.no_command_line_arguments_comment
    )

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

    # uses the .gz file. does not accept any other file. - Ralph
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

    # calls file_data_time parser every time there is a file still. - Ralph
    # .gz is looked into compared to unzipped files to save space. - Ralph
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
            # Rav: We can still set this to the earliest file.
            start = min(files)

    if not files:
        print("No files found.", file=sys.stderr)
        return 1
    # creates a separate multi thread - Ralph
    # Rav: Important distinction - there is no transparent multi-threading
    #      here. This is a multi-process pool. Multi-threading in Python (at
    #      least CPython) is severely held back by the Global Interpreter Lock
    #      (GIL), so that's why we use processes instead.
    if workers > 1:
        # creates workers to run as parallel - Ralph
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
                # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
                # Take the two windows next to each other, merge them, then add
                # the result back to the start. This can be done concurrently
                # by merging multiple pairs.
                # implements a parallel merge sort
                # algorithm that uses multiple worker processes to merge the sliding windows generated from the input data.
                # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
                # Rav: Not sure if I would explicitly call this merge sort.
                #      It's a divide-and-conquer algorithm, but it's not a
                #      merge sort. I could be wrong on this. It always goes
                #      from left to right and more importantly, it reduces
                #      instead of sorts, but it does reduce in a sorted order.
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
                        # Rav: Deque's `extendleft` also reverses the order,
                        #      so we need to reverse it first to counteract it.
                        #      Important to do this or else the merge will be
                        #      incorrect.
                        reverse=True,
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

    multi_protocol_identities: T.Tuple[str, ...]
    carpet_bombing_identities: T.Tuple[str, ...]
    carpet_bombing_multi_protocol_identities: T.Tuple[str, ...]

    # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
    # The variable tracker_arguments is a tuple that
    # contains the attacks and the attack timeout.

    # If the workers variable is greater than 1, the code uses multiple processes to compute the attack types.
    # It creates a process pool using mp.Pool, and then applies the tracker_function to the tracker_arguments tuple using
    # tracker_pool.apply_async
    # for each of the attack types to be tracked. The results are then collected in the tracker_results list.

    # The resulting identities of each type of attack are checked to see if they are unique.
    # If the attack is not unique, '-' is used instead.
    # ------------------------------------------------------------ Ralph -----------------------------------------------------------------------
    if not do_not_compute_attack_types:
        tracker_arguments = (attacks, attack_timeout)
        if workers > 1:
            with STDERR_LOCK:
                print("Computing attack types...", file=sys.stderr)
            with mp.Pool(workers) as tracker_pool:
                # Rav: First, gather up the three tasks and begin them.
                tracker_tasks = [
                    tracker_pool.apply_async(
                        tracker_function,
                        tracker_arguments,
                    )
                    for tracker_function in (
                        track_attack_multi_protocol,
                        track_attack_carpet_bombing,
                        track_attack_carpet_bombing_multi_protocol,
                    )
                ]

                tracker_results = []
                for tracker_task in tracker_tasks:
                    # Rav: Now collect them in the order of the task gathering.
                    tracker_task.wait()
                    tracker_results.append(tracker_task.get())

                # Rav: Finally, unpack the results. Again, they are in order.
                (
                    carpet_bombing_multi_protocol_identities,
                    carpet_bombing_multi_protocol_counts,
                ) = tracker_results.pop()
                (
                    carpet_bombing_identities,
                    carpet_bombing_counts,
                ) = tracker_results.pop()
                (
                    multi_protocol_identities,
                    multi_protocol_counts,
                ) = tracker_results.pop()
        else:
            # NOTE: Rav: This is very likely to be faster on large attack
            # counts than the above due to IPC overhead, pickling, etc.
            print("Computing attack types...", file=sys.stderr)
            (
                multi_protocol_identities,
                multi_protocol_counts,
            ) = track_attack_multi_protocol(*tracker_arguments)
            (
                carpet_bombing_identities,
                carpet_bombing_counts,
            ) = track_attack_carpet_bombing(*tracker_arguments)
            (
                carpet_bombing_multi_protocol_identities,
                carpet_bombing_multi_protocol_counts,
            ) = track_attack_carpet_bombing_multi_protocol(*tracker_arguments)

        if not all_unique_attack_identities:
            multi_protocol_identities = tuple(
                (
                    identity
                    if multi_protocol_identities.count(identity) > 1
                    else "-"
                )
                for identity in multi_protocol_identities
            )
            carpet_bombing_identities = tuple(
                (
                    identity
                    if carpet_bombing_identities.count(identity) > 1
                    else "-"
                )
                for identity in carpet_bombing_identities
            )
            carpet_bombing_multi_protocol_identities = tuple(
                (
                    identity
                    if carpet_bombing_multi_protocol_identities.count(identity)
                    > 1
                    else "-"
                )
                for identity in carpet_bombing_multi_protocol_identities
            )
    else:  # Rav: Just to silence an unbound warning.
        multi_protocol_identities = ()
        multi_protocol_counts = ()
        carpet_bombing_identities = ()
        carpet_bombing_counts = ()
        carpet_bombing_multi_protocol_identities = ()
        carpet_bombing_multi_protocol_counts = ()

    if attacks:
        final_attack = attacks[-1]
        if final_attack.observed_last is not None:
            final_observation = final_attack.observed_last
        else:
            final_observation = final_attack.observed_first
    else:
        final_observation = end  # Rav: Just to silence an unbound warning.

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
        end="",
    )
    if not do_not_compute_attack_types:
        print(
            "|MP_id",
            "CB_id",
            "CBMP_id",
            "MP_cnt",
            "CB_cnt",
            "CBMP_cnt",
            sep="|",
        )
    else:
        print()

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
        end="",
    )

    if not do_not_compute_attack_types:
        print(
            "|multi_protocol_identity",
            "carpet_bombing_identity",
            "carpet_bombing_multi_protocol_identity",
            "multi_protocol_count",
            "carpet_bombing_count",
            "carpet_bombing_multi_protocol_count",
            sep="|",
        )
    else:
        print()

    if not no_command_line_arguments_comment:
        print("#", " ".join(sys.argv))

    for index, attack in enumerate(attacks):
        # Rav: The script is fast enough that we can just do this here.
        if attack.packets < minimum_packets:
            continue

        if __debug__:
            if attack.observed_last is not None:
                assert attack.observed_first <= attack.observed_last

        # TODO: Rav: What behaviour do we want for attacks that are still
        # ongoing (i.e., haven't timed out) after the end given by the user?
        # For now, I'll just use the final timestamp observed and append "+" to
        # the start of it. Shouldn't break integer parsers (good ones at
        # least). Ignored when files were explicitly passed.
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
            end="",
        )

        if not do_not_compute_attack_types:
            print(
                f"|{multi_protocol_identities[index]}",
                carpet_bombing_identities[index],
                carpet_bombing_multi_protocol_identities[index],
                multi_protocol_counts[index],
                carpet_bombing_counts[index],
                carpet_bombing_multi_protocol_counts[index],
                sep="|",
            )
        else:
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
