#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.

import argparse
import errno
import glob
import logging
import os
import re
import sys
import subprocess
import stat
import difflib

HOST_TARGETS = ["dtc"]
DEFAULT_SKIP_LIST = ["abi"]
MSM_EXTENSIONS = "build/msm_kernel_extensions.bzl"
#ABL_EXTENSIONS = "build/abl_extensions.bzl"
DEFAULT_MSM_EXTENSIONS_SRC = "../msm-kernel/msm_kernel_extensions.bzl"
#DEFAULT_ABL_EXTENSIONS_SRC = "../bootable/bootloader/edk2/abl_extensions.bzl"
DEFAULT_OUT_DIR = "{workspace}/out/msm-kernel-{target}-{variant}"

CURR_DIR = os.getcwd()
DEFAULT_CACHE_DIR = os.path.join(CURR_DIR, 'bazel-cache')
if not os.path.exists(DEFAULT_CACHE_DIR):
   os.makedirs(DEFAULT_CACHE_DIR)

os.environ['TEST_TMPDIR'] = DEFAULT_CACHE_DIR

class Target:
    def __init__(self, workspace, target, variant, bazel_label, out_dir=None):
        self.workspace = workspace
        self.target = target
        self.variant = variant
        self.bazel_label = bazel_label
        self.out_dir = out_dir

    def __lt__(self, other):
        return len(self.bazel_label) < len(other.bazel_label)

    def get_out_dir(self, suffix=None):
        if self.out_dir:
            out_dir = self.out_dir
        else:
            # Mirror the logic in msm_common.bzl:get_out_dir()
            if "allyes" in self.target:
                target_norm = self.target.replace("_", "-")
            else:
                target_norm = self.target.replace("-", "_")

            variant_norm = self.variant.replace("-", "_")

            out_dir = DEFAULT_OUT_DIR.format(
                workspace = self.workspace, target=target_norm, variant=variant_norm
            )

        if suffix:
            return os.path.join(out_dir, suffix)
        else:
            return out_dir

class BazelBuilder:
    """Helper class for building with Bazel"""

    def __init__(self, target_list, skip_list, out_dir, cache_dir, dry_run, gki_headers, module, project, variant, chipname, user_opts):
        self.workspace = os.path.realpath(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
        )
        self.bazel_bin = os.path.join(self.workspace, "tools", "bazel")
        if not os.path.exists(self.bazel_bin):
            logging.error("failed to find Bazel binary at %s", self.bazel_bin)
            sys.exit(1)
        self.kernel_dir = os.path.basename(
            (os.path.dirname(os.path.realpath(__file__)))
        )

        for t, v in target_list:
            if not t or not v:
                logging.error("invalid target_variant combo \"%s_%s\"", t, v)
                sys.exit(1)

        self.bazel_cache = "--output_user_root=" + cache_dir
        self.target_list = target_list
        self.skip_list = skip_list
        self.dry_run = dry_run
        self.gki_headers = gki_headers
        self.user_opts = user_opts
        self.process_list = []
        self.module = module
        self.project = project
        self.variant = variant
        self.chipname = chipname
        self.prepare_sec_env_files()
        self.prepare_sec_localversion_files()

        if len(self.target_list) > 1 and out_dir:
            logging.error("cannot specify multiple targets with one out dir")
            sys.exit(1)
        else:
            self.out_dir = out_dir

        self.setup_extensions()
        self.change_file_permission()

    def __del__(self):
        for proc in self.process_list:
            try:
                proc.kill()
                proc.wait()
            except OSError:
                pass

    def setup_extensions(self):
        """Set up the extension files if needed"""
        for (ext, def_src) in [
            (MSM_EXTENSIONS, DEFAULT_MSM_EXTENSIONS_SRC),
            #(ABL_EXTENSIONS, DEFAULT_ABL_EXTENSIONS_SRC),
        ]:
            ext_path = os.path.join(self.workspace, ext)
            # If the file doesn't exist or is a dead link, link to the default
            try:
                os.stat(ext_path)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    logging.info(
                        "%s does not exist or is a broken symlink... linking to default at %s",
                        ext,
                        def_src,
                    )
                    if os.path.islink(ext_path):
                        os.unlink(ext_path)
                    os.symlink(def_src, ext_path)
                else:
                    raise e

    def get_build_targets(self):
        """Query for build targets"""
        logging.info("Querying build targets...")

        targets = []
        for t, v in self.target_list:
            if v == "ALL":
                if self.out_dir:
                    logging.error("cannot specify multiple targets (ALL variants) with one out dir")
                    sys.exit(1)

                skip_list_re = [
                    re.compile(r"//{}:{}_.*_{}_dist".format(self.kernel_dir, t, s))
                    for s in self.skip_list
                ]
                query = 'filter("{}_.*_dist$", attr(generator_function, define_msm_platforms, {}/...))'.format(
                    t, self.kernel_dir
                )
            else:
                skip_list_re = [
                    re.compile(r"//{}:{}_{}_{}_dist".format(self.kernel_dir, t, v, s))
                    for s in self.skip_list
                ]
                if self.module:
                    query = 'filter("{}_{}_{}.*_dist$", attr(generator_function, define_msm_platforms, {}/...))'.format(
                        t, v, self.module, self.kernel_dir
                    )
                else:
                    query = 'filter("{}_{}.*_dist$", attr(generator_function, define_msm_platforms, {}/...))'.format(
                        t, v, self.kernel_dir
                    )

            cmdline = [
                self.bazel_bin,
                self.bazel_cache,
                "query",
                "--ui_event_filters=-info",
                "--noshow_progress",
                query,
            ]

            logging.debug('Running "%s"', " ".join(cmdline))

            try:
                query_cmd = subprocess.Popen(
                    cmdline, cwd=self.workspace, stdout=subprocess.PIPE
                )
                self.process_list.append(query_cmd)
                label_list = [l.decode("utf-8") for l in query_cmd.stdout.read().splitlines()]
            except Exception as e:
                logging.error(e)
                sys.exit(1)

            self.process_list.remove(query_cmd)

            if not label_list:
                logging.error(
                    "failed to find any Bazel targets for target/variant combo %s_%s",
                    t,
                    v,
                )
                sys.exit(1)

            for label in label_list:
                if any((skip_re.match(label) for skip_re in skip_list_re)):
                    continue

                if v == "ALL":
                    real_variant = re.search(
                        r"//{}:{}_([^_]+)_".format(self.kernel_dir, t), label
                    ).group(1)
                else:
                    real_variant = v

                targets.append(
                    Target(self.workspace, t, real_variant, label, self.out_dir)
                )

        # Sort build targets by label string length to guarantee the base target goes
        # first when copying to output directory
        targets.sort()

        return targets

    def clean_legacy_generated_files(self):
        """Clean generated files from legacy build to avoid conflicts with Bazel"""
        for f in glob.glob("{}/msm-kernel/arch/arm64/configs/vendor/*_defconfig".format(self.workspace)):
            os.remove(f)

        f = os.path.join(self.workspace, "bootable", "bootloader", "edk2", "Conf", ".AutoGenIdFile.txt")
        if os.path.exists(f):
            os.remove(f)

        for root, _, files in os.walk(os.path.join(self.workspace, "bootable")):
            for f in files:
                if f.endswith(".pyc"):
                    os.remove(os.path.join(root, f))

    def bazel(
        self,
        bazel_subcommand,
        targets,
        extra_options=None,
        bazel_target_opts=None,
    ):
        """Execute a bazel command"""
        cmdline = [self.bazel_bin, self.bazel_cache, bazel_subcommand]
        if extra_options:
            cmdline.extend(extra_options)
        cmdline.extend([t.bazel_label for t in targets])
        if bazel_target_opts is not None:
            cmdline.extend(["--"] + bazel_target_opts)

        cmdline_str = " ".join(cmdline)
        try:
            logging.info('Running "%s"', cmdline_str)
            build_proc = subprocess.Popen(cmdline_str, cwd=self.workspace, shell=True)
            self.process_list.append(build_proc)
            build_proc.wait()
            if build_proc.returncode != 0:
                sys.exit(build_proc.returncode)
        except Exception as e:
            logging.error(e)
            sys.exit(1)

        self.process_list.remove(build_proc)

    def build_targets(self, targets):
        """Run "bazel build" on all targets in parallel"""
        self.bazel("build", targets, extra_options=self.user_opts)

    def run_targets(self, targets):
        """Run "bazel run" on all targets in serial (since bazel run cannot have multiple targets)"""
        for target in targets:
            # Set the output directory based on if it's a host target
            if any(
                re.match(r"//{}:.*_{}_dist".format(self.kernel_dir, h), target.bazel_label)
                    for h in HOST_TARGETS
            ):
                out_dir = target.get_out_dir("host")
            else:
                out_dir = target.get_out_dir("dist")
            self.bazel(
                "run",
                [target],
                extra_options=self.user_opts,
                bazel_target_opts=["--dist_dir", out_dir]
            )
            self.write_opts(out_dir)

    def run_menuconfig(self):
        """Run menuconfig on all target-variant combos class is initialized with"""
        for t, v in self.target_list:
            menuconfig_label = "//{}:{}_{}_config".format(self.kernel_dir, t, v)
            menuconfig_target = [Target(self.workspace, t, v, menuconfig_label, self.out_dir)]
            self.bazel("run", menuconfig_target, bazel_target_opts=["menuconfig"])

    def write_opts(self, out_dir):
        with open(os.path.join(out_dir, "build_opts.txt"), "w") as opt_file:
            if self.user_opts:
                opt_file.write("{}".format("\n".join(self.user_opts)))
            opt_file.write("\n")

    def check_diff(self, file1, file2):
        with open(file1, 'r') as f1, open(file2, 'r') as f2:
            lines1 = f1.readlines()
            lines2 = f2.readlines()

        diff = difflib.unified_diff(lines1, lines2)
        return any(diff)

    def build(self):
        """Determine which targets to build, then build them"""
        targets_to_build = self.get_build_targets()

        if not targets_to_build:
            logging.error("no targets to build")
            sys.exit(1)

        if self.skip_list:
            self.user_opts.extend(["--//msm-kernel:skip_{}=true".format(s) for s in self.skip_list])

        self.user_opts.extend([
            "--user_kmi_symbol_lists=//msm-kernel:android/abi_gki_aarch64_qcom",
            "--ignore_missing_projects",
            "--incompatible_sandbox_hermetic_tmp=false",
            "--nozstd_dwarf_compression",
        ])

        if self.dry_run:
            self.user_opts.append("--nobuild")

        if self.module == "abl":
            self.user_opts.extend(["--//bootable/bootloader/edk2:project_fullname={} --//bootable/bootloader/edk2:target_build_variant={} --//bootable/bootloader/edk2:chipname={}".format(self.project, self.variant, self.chipname)])

        try:
            if self.gki_headers:
                gki_files_path = os.path.join(self.workspace, 'msm-kernel/files_gki_aarch64.txt')
                gki_f = open(gki_files_path, 'r')
                gki_files = gki_f.readlines()
                common_d = os.path.join(self.workspace, "common")
                msm_d = os.path.join(self.workspace, "msm-kernel")
                diff_files = []
                for f in gki_files:
                    if ".h" in f:
                        logging.info('GKI header file...%s', f)
                        f=f.strip()
                        common_f = os.path.join(common_d, f)
                        msm_f = os.path.join(msm_d, f)
                        if self.check_diff(common_f, msm_f):
                            diff_files.append(f)
                        os.remove(msm_f)
                        os.symlink(common_f, msm_f)
                gki_f.close()

                logging.debug(
                    "Differences have been detected in the following files within the 'common' and 'msm-kernel' folders. These differences might cause build errors or unexpected behaviors.\n%s",
                    "\n".join(diff_files)
                )

            logging.debug(
                "Building the following targets:\n%s",
                "\n".join([t.bazel_label for t in targets_to_build])
            )

            self.clean_legacy_generated_files()

            logging.info("Building targets...")
            self.build_targets(targets_to_build)

            if not self.dry_run:
                self.run_targets(targets_to_build)
        finally:
            if self.gki_headers:
                status = subprocess.Popen(["git", "checkout",
                                     "--pathspec-from-file=files_gki_aarch64.txt"],
                                    cwd=os.path.join(self.workspace, "msm-kernel"))
                status.wait()
                if status.returncode != 0:
                    logging.error("Failed to restore headers from symlinks")
                    logging.error("You might want to check your msm-kernel tree")

    def prepare_sec_env_files(self):
        self.sec_env_keys = {
            "LOCALVERSION": 1,
            "TARGET_BUILD_VARIANT": 1,
            "BUILD_NUMBER": 1,
            "CL_SYNC": 1,
            "SEC_FACTORY_BUILD":1,
            "SEC_BUILD_OPTION_DEBUG_LEVEL": 1,
            "SEC_PRODUCT_SHIP": 1,
            "SEC_BUILD_OPTION_KNOX_CSB": 1,
            "SEC_BUILD_CONF_MODEL_SIGNING_NAME": 1,
            "SEC_BUILD_OPTION_CARRIER_ID": 1,
            "SEC_BUILD_OPTION_EXTRA_BUILD_CONFIG": 1,
            "PROJECT_REGION": 1,
            "SEC_QUICKBUILD_ID": 1,
        }
        self.write_sec_env_mk_foramt(os.path.join(self.workspace, "common", "scripts", "sec_env.mk"))
        self.write_sec_env_mk_foramt(os.path.join(self.workspace, "msm-kernel", "scripts", "sec_env.mk"))
        self.write_sec_env_sh_foramt(os.path.join(self.workspace, "msm-kernel", "build.config.sec_env"))
        if 'abl' not in self.skip_list:
            self.write_sec_env_mk_foramt(os.path.join(self.workspace, "bootable/bootloader/edk2", "sec_env.mk"))

    def write_sec_env_sh_foramt(
        self,
        filename
    ):
        f = open(filename, 'w')
        for key, value in os.environ.items():
            if key in self.sec_env_keys:
                data = "{}={}\n".format(key, value)
                f.write(data)
        f.close()

    def write_sec_env_mk_foramt(
        self,
        filename
    ):
        f = open(filename, 'w')
        for key, value in os.environ.items():
            if key in self.sec_env_keys:
                data = "{}:={}\n".format(key, value)
                f.write(data)
        f.close()

    def prepare_sec_localversion_files(self):
        self.write_sec_localversion(os.path.join(self.workspace, "common", "localversion"))
        self.write_sec_localversion(os.path.join(self.workspace, "msm-kernel", "localversion"))

    def write_sec_localversion(
        self,
        filename
    ):
        cl_sync = os.environ.get('CL_SYNC')
        target_build_variant = os.environ.get('TARGET_BUILD_VARIANT')
        build_number = os.environ.get('BUILD_NUMBER')
        localversion = "-{}-abogki{}".format(cl_sync, build_number)
        if target_build_variant == 'userdebug':
            localversion = "-{}-{}-abogki{}".format(cl_sync, "ud", build_number)
        elif target_build_variant == 'eng':
            localversion = "-{}-{}-abogki{}".format(cl_sync, "en", build_number)

        f = open(filename, 'w')
        f.write(localversion)
        f.close()

    def change_file_permission(self):
        file_permission = {
            os.path.join(self.workspace, "common", "android", "abi_gki_aarch64_qcom"): stat.S_IREAD | stat.S_IWRITE,
            os.path.join(self.workspace, "common", "android", "abi_gki_protected_exports_aarch64"): stat.S_IREAD | stat.S_IWRITE,
            os.path.join(self.workspace, "msm-kernel", "modules.vendor_blocklist.msm.*"): stat.S_IREAD | stat.S_IWRITE,
        }

        for name, permission in file_permission.items():
            for filename in glob.glob(name):
                os.chmod(filename, permission)


def main():
    """Main script entrypoint"""
    parser = argparse.ArgumentParser(description="Build kernel platform with Bazel")

    parser.add_argument(
        "-t",
        "--target",
        metavar=("TARGET", "VARIANT"),
        action="append",
        nargs=2,
        required=True,
        help='Target and variant to build (e.g. -t kalama gki). May be passed multiple times. A special VARIANT may be passed, "ALL", which will build all variants for a particular target',
    )
    parser.add_argument(
        "-s",
        "--skip",
        metavar="BUILD_RULE",
        action="append",
        default=[],
        help="Skip specific build rules (e.g. --skip abl will skip the //msm-kernel:<target>_<variant>_abl build)",
    )
    parser.add_argument(
        "-o",
        "--out_dir",
        metavar="OUT_DIR",
        help='Specify the output distribution directory (by default, "$PWD/out/msm-kernel-<target>-variant")',
    )
    parser.add_argument(
        "--log",
        metavar="LEVEL",
        default="debug",
        choices=["debug", "info", "warning", "error"],
        help="Log level (debug, info, warning, error)",
    )
    parser.add_argument(
        "-c",
        "--menuconfig",
        action="store_true",
        help="Run menuconfig for <target>-<variant> and exit without building",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="Perform a dry-run of the build which will perform loading/analysis of build files",
    )
    parser.add_argument(
        "--cache_dir",
        metavar="CACHE_DIR",
        default=DEFAULT_CACHE_DIR,
        help='Specify the bazel cache directory (defaults to ' + DEFAULT_CACHE_DIR + ')'
    )
    parser.add_argument(
        "-g",
        "--gki-headers",
        action="store_true",
        help="Compile with common headers instead of msm-kernel"
    )
    parser.add_argument(
        "-m",
        "--module",
        metavar="MODULE",
        help="Specify the build module (e.g. --module abl will only process the //msm-kernel:<target>_<variant>_abl build)",
    )
    parser.add_argument(
        "-p",
        "--project",
        metavar="PROJECT",
        help="Specify the project fullname (e.g. --project mu3q_usa_singlew)",
    )
    parser.add_argument(
        "-v",
        "--variant",
        metavar="VARIANT",
	default="eng",
        help="Specify the build variant (e.g. --variant eng)",
    )
    parser.add_argument(
        "-n",
        "--chipname",
        metavar="CHIPNAME",
        default="",
        help="Specify the build chipname (e.g. --chipname sm8750), it's set in sm8750 file under buildscript/boot_external/bootloaders",
    )

    args, user_opts = parser.parse_known_args(sys.argv[1:])

    logging.basicConfig(
        level=getattr(logging, args.log.upper()),
        format="[{}] %(levelname)s: %(message)s".format(os.path.basename(sys.argv[0])),
    )

    args.skip.extend(DEFAULT_SKIP_LIST)

    builder = BazelBuilder(
        args.target,
        args.skip,
        args.out_dir,
        args.cache_dir,
        args.dry_run,
        args.gki_headers,
        args.module,
        args.project,
        args.variant,
        args.chipname,
        user_opts
    )
    try:
        if args.menuconfig:
            builder.run_menuconfig()
        else:
            builder.build()
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt... exiting")
        del builder
        sys.exit(1)

    if args.dry_run:
        logging.info("Dry-run completed successfully!")
    else:
        logging.info("Build completed successfully!")

if __name__ == "__main__":
    main()
