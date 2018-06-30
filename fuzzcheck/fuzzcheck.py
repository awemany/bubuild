#!/usr/bin/env python3
# Bitcoin Unlimited fuzzer and coverage utility
# (C)opyright 2018 The Bitcoin Unlimited developers
#
#
import time
import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

import argparse
import glob
import os
import os.path
import struct
#import shutil
import collections
import re

def get_fuzz_cases(args):
    """ Return dictionary of fuzz cases, mapping fuzz case number to name string. """
    binary = args.bitcoin_fuzzy
    fuzznames = os.popen(
        binary+" list_tests",
        ).readlines()

    if not len(fuzznames):
        raise RuntimeError("Problem calling '%s'." % binary)

    try:
        return {
            int(fn[0]) : fn[1] for fn in
            [x.split() for x in fuzznames] }
    except:
        raise RuntimeError("Cannot parse output of '%s'." % binary)

def ensuredir(path):
    if os.path.isdir(path):
        return
    else:
        os.mkdir(path)

def fuzzcheck_split(args):
    log.info("Please make sure to run this script on a same-endianness archictecture as the fuzzer job!")
    log.info("Input directory: %s", args.input_directory)
    log.info("Output directory: %s", args.output_directory)

    ensuredir(args.output_directory)

    # count number of special cases
    stats = collections.Counter()

    fuzz_cases = get_fuzz_cases(args)

    for fn in (
            glob.glob(os.path.join(
                args.input_directory,
                "id*"))):
        log.info("Processing %s.", fn)
        # FIXME: maybe fix endianess to specific value in test_bitcoin_fuzzy.cpp?

        fuzz_id_bytes = open(fn, "rb").read(4)
        if len(fuzz_id_bytes) < 4:
            log.info("Skipping, not enough data in fuzz case.")
            continue

        fuzz_id = struct.unpack("@I", fuzz_id_bytes)[0]
        if fuzz_id not in fuzz_cases:
            log.info("Fuzz case id %d not found in list of cases. Skipping.",
                     fuzz_id)
            continue

        case_str = fuzz_cases[fuzz_id]
        log.info("This is a test of %s.", case_str)

        target_dir = os.path.join(
            args.output_directory,
            case_str)
        dest_fn = os.path.join(target_dir, os.path.basename(fn))
        fcout_fn = os.path.join(target_dir,
                                "fcout." + os.path.basename(fn))

        log.info("Destination file: %s", dest_fn)
        log.info("Fuzz case output file: %s", fcout_fn)

        ensuredir(target_dir)
        with open(dest_fn, "wb") as outf:
            outf.write(open(fn, "rb").read()[4:])
        os.system("%s +%s < %s > %s" % (
                  args.bitcoin_fuzzy,
                  case_str,
                  dest_fn, fcout_fn))

        stats[case_str]+=1

    log.info("Fuzz case stats:")
    total = 0
    for name, count in stats.most_common():
        log.info("%5d %20s", count, name)
        total += count
    log.info("Total: %d", total)


def fuzzcheck_run(args):
    log.info("Please make sure to run this script on a same-endianness archictecture as the fuzzer job!")
    log.info("Input directory: %s", args.input_directory)
    log.info("Output directory: %s", args.output_directory)

    ensuredir(args.output_directory)

    fuzz_cases = get_fuzz_cases(args)

    dir2case = { re.compile(r".+/%s$" % name) : name for name in fuzz_cases.values() }

    fnre = re.compile(r"^id.+")

    summary = []

    sum_mismatch = 0

    for dirpath, dirnames, filenames in os.walk(args.input_directory):
        # FIXME: not particularly efficient ...
        for regexp, name in dir2case.items():
            if regexp.match(dirpath):
                log.info("Current directory is '%s', assuming test cases '%s'.", dirpath, name)
                case_str = name
                break
        else:
            log.info("Directory '%s' contains unknown cases. Skipping.", dirpath)
            continue

        for fn in filenames:
            if fnre.match(fn):
                log.info("Looking at case '%s'.", fn)

                # FIXME: some code duplication with 'split' here
                target_dir = os.path.join(
                    args.output_directory,
                    case_str)

                testout_fn = os.path.join(target_dir,
                                        "testout." + os.path.basename(fn))

                fcout_fn = os.path.join(dirpath,
                                    "fcout." + os.path.basename(fn))

                try:
                    open(fcout_fn, "rb").read()
                except IOError:
                    log.info("Cannot open fuzz case gold file '%s'. Skipping." % fcout_fn)
                    continue

                log.info("Output file: %s", testout_fn)
                log.info("Gold standard file: %s", fcout_fn)

                ensuredir(target_dir)

                tbc_cmd=("%s +%s < %s > %s" % (
                      args.bitcoin_fuzzy,
                      case_str,
                      os.path.join(dirpath, fn), testout_fn))
                log.info("Executing '%s'.", tbc_cmd)

                time_start = time.time()
                os.system(tbc_cmd)
                time_end = time.time()
                duration = time_end - time_start
                log.info("Duration: %d sec.", duration)

                testout_data = open(testout_fn, "rb").read()
                fcout_data = open(fcout_fn, "rb").read()

                if testout_data != fcout_data:
                    log.error("Data in '%s' (%d bytes) differs from gold standard in '%s' (%d bytes).",
                              testout_fn, len(testout_data), fcout_fn, len(fcout_data))
                else:
                    log.info("Data (%d bytes) in '%s' matches gold standard in '%s'.",
                             len(testout_data), testout_fn, fcout_fn)

                sum_mismatch += int(testout_data != fcout_data)

                summary.append(
                    {   "case_str" : case_str,
                        "input" :  fn,
                        "matches" : testout_data == fcout_data,
                        "output_length" : len(testout_data),
                        "gold_length" : len(fcout_data),
                        "duration" : duration
                        })

    with open(args.summary, "w") as outf:
        print("# Time: %s" % time.asctime(), file = outf)
        print("# Total number of mismatches: %d" % sum_mismatch, file = outf)
        for entry in sorted(summary, key = lambda x : x["case_str"]):
            print("%(case_str)30s %(input)60s %(matches)1d "
                  "%(output_length)6d %(gold_length)6d %(duration)7.2f" % entry,
                  file = outf)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="fuzzcheck")
    subparsers = parser.add_subparsers()

    parser_split = subparsers.add_parser("split", help="Split up fuzz-all files")

    parser_split.set_defaults(func = fuzzcheck_split)

    parser_split.add_argument("bitcoin_fuzzy", type=str,
                              help="Path to test_bitcoin_fuzzy binary.")
    parser_split.add_argument("input_directory",
                              help="Input directory with id* files as output from fuzzer.", type=str)
    parser_split.add_argument("output_directory",
                              help="Output directory with hierarchy of special case fuzz files.")

    parser_run = subparsers.add_parser("run", help="Run test_bitcoin_fuzzy with fuzz files. Automatically extracts run information from file path. Produce output files using '+' option to test_bitcoin_fuzzy.")

    parser_run.set_defaults(func = fuzzcheck_run)

    parser_run.add_argument("bitcoin_fuzzy", type=str,
                              help="Path to test_bitcoin_fuzzy binary.")
    parser_run.add_argument("input_directory",
                              help="Input directory with id* files (as output from fuzzer) to test.", type=str)
    parser_run.add_argument("output_directory",
                                 help="Output directory which will be filled with output from test_bitcoin_fuzzy", type=str)
    parser_run.add_argument("summary",
                            help="Output summary text file.", type=str)

    args = parser.parse_args()

    if "func" not in args:
        print("Need to specify subcommand.")
        exit(1)

    args.func(args)
