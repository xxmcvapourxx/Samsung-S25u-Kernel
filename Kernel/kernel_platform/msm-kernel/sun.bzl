load(":target_variants.bzl", "la_variants")
load(":msm_kernel_la.bzl", "define_msm_la")
load(":image_opts.bzl", "boot_image_opts")
load(":sec_bsp.bzl", "sec_bsp")
load(":kunit.bzl", "kunit_module_list")
load(":sec_block.bzl", "sec_block")
load(":lego.bzl", "lego_module_list")
load(":sec_usb.bzl", "sec_usb")
load(":sec_sensor.bzl", "sec_sensor")
load(":sec_audio.bzl", "sec_audio")
load(":sec_power.bzl", "sec_power")
load(":sec_mm.bzl", "sec_mm")
load(":sec_ipc.bzl", "sec_ipc")

target_name = "sun"

def define_sun():
    _sun_in_tree_modules = [
        # keep sorted
        "arch/arm64/gunyah/gh_arm_drv.ko",
        "drivers/base/regmap/qti-regmap-debugfs.ko",
        "drivers/block/zram/zram.ko",
        "drivers/bus/mhi/devices/mhi_dev_satellite.ko",
        "drivers/bus/mhi/devices/mhi_dev_uci.ko",
        "drivers/bus/mhi/host/mhi.ko",
        "drivers/char/rdbg.ko",
        "drivers/clk/clk-scmi.ko",
        "drivers/clk/qcom/cambistmclkcc-sun.ko",
        "drivers/clk/qcom/cambistmclkcc-tuna.ko",
        "drivers/clk/qcom/camcc-sun.ko",
        "drivers/clk/qcom/camcc-tuna.ko",
        "drivers/clk/qcom/clk-dummy.ko",
        "drivers/clk/qcom/clk-qcom.ko",
        "drivers/clk/qcom/clk-rpmh.ko",
        "drivers/clk/qcom/debugcc-sun.ko",
        "drivers/clk/qcom/dispcc-sun.ko",
        "drivers/clk/qcom/evacc-sun.ko",
        "drivers/clk/qcom/evacc-tuna.ko",
        "drivers/clk/qcom/gcc-kera.ko",
        "drivers/clk/qcom/gcc-sun.ko",
        "drivers/clk/qcom/gcc-tuna.ko",
        "drivers/clk/qcom/gdsc-regulator.ko",
        "drivers/clk/qcom/gpucc-sun.ko",
        "drivers/clk/qcom/gpucc-tuna.ko",
        "drivers/clk/qcom/tcsrcc-sun.ko",
        "drivers/clk/qcom/tcsrcc-tuna.ko",
        "drivers/clk/qcom/videocc-sun.ko",
        "drivers/clk/qcom/videocc-tuna.ko",
        "drivers/cpufreq/qcom-cpufreq-thermal.ko",
        "drivers/cpuidle/governors/qcom_lpm.ko",
        "drivers/crypto/qcom-rng.ko",
        "drivers/devfreq/governor_gpubw_mon.ko",
        "drivers/devfreq/governor_msm_adreno_tz.ko",
        "drivers/dma-buf/heaps/qcom_dma_heaps.ko",
        "drivers/dma/qcom/bam_dma.ko",
        "drivers/dma/qcom/msm_gpi.ko",
        "drivers/edac/qcom_edac.ko",
        "drivers/firmware/arm_scmi/qcom_scmi_vendor.ko",
        "drivers/firmware/qcom-scm.ko",
        "drivers/firmware/qcom/si_core/mem_object.ko",
        "drivers/firmware/qcom/si_core/si_core_module.ko",
        "drivers/gpu/drm/bridge/lt9611uxc.ko",
        "drivers/gpu/drm/display/drm_display_helper.ko",
        "drivers/gpu/drm/display/drm_dp_aux_bus.ko",
        "drivers/hwmon/hwmon.ko",
        # "drivers/hwmon/qti_amoled_ecm.ko",
        "drivers/hwspinlock/qcom_hwspinlock.ko",
        "drivers/hwtracing/coresight/coresight.ko",
        "drivers/hwtracing/coresight/coresight-csr.ko",
        "drivers/hwtracing/coresight/coresight-cti.ko",
        "drivers/hwtracing/coresight/coresight-dummy.ko",
        "drivers/hwtracing/coresight/coresight-funnel.ko",
        "drivers/hwtracing/coresight/coresight-qmi.ko",
        "drivers/hwtracing/coresight/coresight-remote-etm.ko",
        "drivers/hwtracing/coresight/coresight-replicator.ko",
        "drivers/hwtracing/coresight/coresight-stm.ko",
        "drivers/hwtracing/coresight/coresight-tgu.ko",
        "drivers/hwtracing/coresight/coresight-tmc.ko",
        "drivers/hwtracing/coresight/coresight-tmc-sec.ko",
        "drivers/hwtracing/coresight/coresight-tpda.ko",
        "drivers/hwtracing/coresight/coresight-tpdm.ko",
        "drivers/hwtracing/coresight/coresight-trace-noc.ko",
        "drivers/hwtracing/coresight/coresight-uetm.ko",
        "drivers/hwtracing/stm/stm_console.ko",
        "drivers/hwtracing/stm/stm_core.ko",
        "drivers/hwtracing/stm/stm_ftrace.ko",
        "drivers/hwtracing/stm/stm_heartbeat.ko",
        "drivers/hwtracing/stm/stm_p_ost.ko",
        "drivers/i2c/busses/i2c-msm-geni.ko",
        "drivers/i3c/master/i3c-master-msm-geni.ko",
        "drivers/iio/adc/qcom-spmi-adc5-gen3.ko",
        "drivers/iio/adc/qcom-vadc-common.ko",
        # "drivers/iio/adc/qti-glink-adc.ko",
        "drivers/input/misc/pm8941-pwrkey.ko",
        # "drivers/input/misc/qcom-hv-haptics.ko",
        "drivers/interconnect/qcom/icc-bcm-voter.ko",
        "drivers/interconnect/qcom/icc-debug.ko",
        "drivers/interconnect/qcom/icc-rpmh.ko",
        "drivers/interconnect/qcom/qnoc-qos.ko",
        "drivers/interconnect/qcom/qnoc-sun.ko",
        "drivers/interconnect/qcom/qnoc-tuna.ko",
        "drivers/iommu/arm/arm-smmu/arm_smmu.ko",
        "drivers/iommu/iommu-logger.ko",
        "drivers/iommu/msm_dma_iommu_mapping.ko",
        "drivers/iommu/qcom_iommu_debug.ko",
        "drivers/iommu/qcom_iommu_util.ko",
        "drivers/irqchip/msm_show_resume_irq.ko",
        "drivers/irqchip/qcom-pdc.ko",
        "drivers/leds/flash/leds-qcom-flash.ko",
        "drivers/leds/leds-qti-flash.ko",
        "drivers/leds/rgb/leds-qcom-lpg.ko",
        "drivers/mailbox/msm_qmp.ko",
        "drivers/mailbox/qcom-ipcc.ko",
        "drivers/mfd/qcom-i2c-pmic.ko",
        "drivers/mfd/qcom-spmi-pmic.ko",
        "drivers/misc/qseecom_proxy.ko",
        "drivers/mmc/host/cqhci.ko",
        "drivers/mmc/host/sdhci-msm.ko",
        "drivers/nvmem/nvmem_qcom-spmi-sdam.ko",
        "drivers/nvmem/nvmem_qfprom.ko",
        "drivers/pci/controller/pci-msm-drv.ko",
        "drivers/perf/qcom_llcc_pmu.ko",
        "drivers/phy/qualcomm/phy-qcom-ufs.ko",
        "drivers/phy/qualcomm/phy-qcom-ufs-qmp-v4-sun.ko",
        "drivers/phy/qualcomm/phy-qcom-ufs-qrbtc-sdm845.ko",
        "drivers/pinctrl/qcom/pinctrl-kera.ko",
        "drivers/pinctrl/qcom/pinctrl-msm.ko",
        "drivers/pinctrl/qcom/pinctrl-spmi-gpio.ko",
        "drivers/pinctrl/qcom/pinctrl-spmi-mpp.ko",
        "drivers/pinctrl/qcom/pinctrl-sun.ko",
        "drivers/pinctrl/qcom/pinctrl-tuna.ko",
        "drivers/power/reset/qcom-dload-mode.ko",
        "drivers/power/reset/qcom-pon.ko",
        "drivers/power/reset/qcom-reboot-reason.ko",
        "drivers/power/reset/reboot-mode.ko",
        # "drivers/power/supply/qti_battery_charger.ko",
        "drivers/regulator/debug-regulator.ko",
        "drivers/regulator/proxy-consumer.ko",
        # "drivers/regulator/qcom-amoled-regulator.ko",
        "drivers/regulator/qti-fixed-regulator.ko",
        "drivers/regulator/qti-ocp-notifier.ko",
        "drivers/regulator/rpmh-regulator.ko",
        "drivers/regulator/stub-regulator.ko",
        "drivers/remoteproc/qcom_pil_info.ko",
        "drivers/remoteproc/qcom_q6v5.ko",
        "drivers/remoteproc/qcom_q6v5_pas.ko",
        "drivers/remoteproc/qcom_spss.ko",
        "drivers/remoteproc/qcom_sysmon.ko",
        "drivers/remoteproc/rproc_qcom_common.ko",
        "drivers/rpmsg/glink_pkt.ko",
        "drivers/rpmsg/qcom_glink.ko",
        "drivers/rpmsg/qcom_glink_smem.ko",
        "drivers/rpmsg/qcom_glink_spss.ko",
        "drivers/rpmsg/qcom_smd.ko",
        "drivers/rtc/rtc-pm8xxx.ko",
        "drivers/scsi/sg.ko",
        "drivers/slimbus/slim-qcom-ngd-ctrl.ko",
        "drivers/slimbus/slimbus.ko",
        "drivers/soc/qcom/adsp_sleepmon.ko",
        # "drivers/soc/qcom/altmode-glink.ko",
        "drivers/soc/qcom/boot_stats.ko",
        "drivers/soc/qcom/cdsprm.ko",
        # "drivers/soc/qcom/charger-ulog-glink.ko",
        "drivers/soc/qcom/cmd-db.ko",
        "drivers/soc/qcom/cpu_phys_log_map.ko",
        "drivers/soc/qcom/cpucp_fast.ko",
        "drivers/soc/qcom/cpucp_log.ko",
        "drivers/soc/qcom/crm-v2.ko",
        "drivers/soc/qcom/dcc_v2.ko",
        "drivers/soc/qcom/dcvs/bwmon.ko",
        "drivers/soc/qcom/dcvs/cpufreq_stats_scmi_v3.ko",
        "drivers/soc/qcom/dcvs/dcvs_fp.ko",
        "drivers/soc/qcom/dcvs/memlat.ko",
        "drivers/soc/qcom/dcvs/qcom-dcvs.ko",
        "drivers/soc/qcom/dcvs/qcom-pmu-lib.ko",
        "drivers/soc/qcom/dcvs/qcom_scmi_client.ko",
        "drivers/soc/qcom/debug_symbol.ko",
        "drivers/soc/qcom/dmesg_dumper.ko",
        "drivers/soc/qcom/eud.ko",
        "drivers/soc/qcom/gh_tlmm_vm_mem_access.ko",
        "drivers/soc/qcom/gic_intr_routing.ko",
        "drivers/soc/qcom/glink_probe.ko",
        "drivers/soc/qcom/hung_task_enh.ko",
        "drivers/soc/qcom/llcc-qcom.ko",
        "drivers/soc/qcom/llcc_heuristics.ko",
        "drivers/soc/qcom/llcc_perfmon.ko",
        "drivers/soc/qcom/mdt_loader.ko",
        "drivers/soc/qcom/mem-hooks.ko",
        "drivers/soc/qcom/mem-offline.ko",
        "drivers/soc/qcom/mem_buf/mem_buf.ko",
        "drivers/soc/qcom/mem_buf/mem_buf_dev.ko",
        "drivers/soc/qcom/mem_buf/mem_buf_msgq.ko",
        "drivers/soc/qcom/memory_dump_v2.ko",
        "drivers/soc/qcom/memshare/heap_mem_ext_v01.ko",
        "drivers/soc/qcom/memshare/msm_memshare.ko",
        "drivers/soc/qcom/minidump.ko",
        "drivers/soc/qcom/mpam/cpu_mpam.ko",
        "drivers/soc/qcom/mpam/mpam.ko",
        "drivers/soc/qcom/mpam/mpam_msc.ko",
        "drivers/soc/qcom/mpam/mpam_msc_slc.ko",
        "drivers/soc/qcom/mpam/platform_mpam.ko",
        "drivers/soc/qcom/mpam/slc_mpam.ko",
        "drivers/soc/qcom/msm_performance.ko",
        "drivers/soc/qcom/msm_show_epoch.ko",
        "drivers/soc/qcom/panel_event_notifier.ko",
        "drivers/soc/qcom/pcie-pdc.ko",
        "drivers/soc/qcom/pdr_interface.ko",
        # "drivers/soc/qcom/pmic-glink-debug.ko",
        "drivers/soc/qcom/pmic-pon-log.ko",
        "drivers/soc/qcom/qcom_aoss.ko",
        "drivers/soc/qcom/qcom_cpu_vendor_hooks.ko",
        "drivers/soc/qcom/qcom_cpucp.ko",
        "drivers/soc/qcom/qcom_cpuss_sleep_stats_v4.ko",
        "drivers/soc/qcom/qcom_dynamic_ramoops.ko",
        "drivers/soc/qcom/qcom_ice.ko",
        "drivers/soc/qcom/qcom_logbuf_boot_log.ko",
        "drivers/soc/qcom/qcom_logbuf_vendor_hooks.ko",
        "drivers/soc/qcom/qcom_ramdump.ko",
        "drivers/soc/qcom/qcom_rpmh.ko",
        "drivers/soc/qcom/qcom_stats.ko",
        "drivers/soc/qcom/qcom_va_minidump.ko",
        "drivers/soc/qcom/qcom_wdt_core.ko",
        "drivers/soc/qcom/qmi_helpers.ko",
        "drivers/soc/qcom/qsee_ipc_irq_bridge.ko",
        # "drivers/soc/qcom/qti_battery_debug.ko",
        "drivers/soc/qcom/qti_fctl_scmi.ko",
        # "drivers/soc/qcom/qti_pmic_glink.ko",
        "drivers/soc/qcom/secure_buffer.ko",
        "drivers/soc/qcom/smem.ko",
        "drivers/soc/qcom/smp2p.ko",
        "drivers/soc/qcom/smp2p_sleepstate.ko",
        "drivers/soc/qcom/socinfo.ko",
        "drivers/soc/qcom/sps/sps_drv.ko",
        "drivers/soc/qcom/sys_pm_vx.ko",
        "drivers/soc/qcom/sysmon_subsystem_stats.ko",
        "drivers/soc/qcom/tmecom/tmecom-intf.ko",
        "drivers/soc/qcom/wcd_usbss_i2c.ko",
        "drivers/spi/q2spi-geni.ko",
        "drivers/spi/spi-msm-geni.ko",
        "drivers/spmi/spmi-pmic-arb.ko",
        "drivers/spmi/spmi-pmic-arb-debug.ko",
        "drivers/thermal/qcom/bcl_pmic5.ko",
        "drivers/thermal/qcom/bcl_soc.ko",
        "drivers/thermal/qcom/cpu_hotplug.ko",
        "drivers/thermal/qcom/ddr_cdev.ko",
        "drivers/thermal/qcom/gpu_dump_skip_cdev.ko",
        "drivers/thermal/qcom/max31760_fan.ko",
        "drivers/thermal/qcom/qcom-spmi-temp-alarm.ko",
        "drivers/thermal/qcom/qcom_tsens.ko",
        "drivers/thermal/qcom/qti_cpufreq_cdev.ko",
        "drivers/thermal/qcom/qti_devfreq_cdev.ko",
        "drivers/thermal/qcom/qti_qmi_cdev.ko",
        "drivers/thermal/qcom/qti_qmi_sensor_v2.ko",
        "drivers/thermal/qcom/qti_thermal_vendor_hooks.ko",
        "drivers/thermal/qcom/qti_userspace_cdev.ko",
        "drivers/thermal/qcom/thermal_config.ko",
        "drivers/thermal/qcom/thermal_pause.ko",
        "drivers/tty/hvc/hvc_gunyah.ko",
        "drivers/tty/serial/msm_geni_serial.ko",
        "drivers/ufs/host/ufs_qcom.ko",
        "drivers/ufs/host/ufshcd-crypto-qti.ko",
        "drivers/uio/msm_sharedmem/msm_sharedmem.ko",
        "drivers/usb/dwc3/dwc3-msm.ko",
        "drivers/usb/gadget/function/f_fs_ipc_log.ko",
        "drivers/usb/gadget/function/usb_f_ccid.ko",
        "drivers/usb/gadget/function/usb_f_cdev.ko",
        "drivers/usb/gadget/function/usb_f_gsi.ko",
        "drivers/usb/gadget/function/usb_f_qdss.ko",
        "drivers/usb/host/xhci-sideband.ko",
        "drivers/usb/phy/phy-generic.ko",
        "drivers/usb/phy/phy-msm-m31-eusb2.ko",
        "drivers/usb/phy/phy-msm-ssusb-qmp.ko",
        "drivers/usb/phy/phy-qcom-emu.ko",
        "drivers/usb/redriver/nb7vpq904m.ko",
        "drivers/usb/redriver/redriver.ko",
        "drivers/usb/repeater/repeater.ko",
        # "drivers/usb/repeater/repeater-qti-pmic-eusb2.ko",
        # "drivers/usb/typec/ucsi/ucsi_qti_glink.ko",
        "drivers/video/backlight/lcd.ko",
        "drivers/virt/gunyah/gh_ctrl.ko",
        "drivers/virt/gunyah/gh_dbl.ko",
        "drivers/virt/gunyah/gh_irq_lend.ko",
        "drivers/virt/gunyah/gh_mem_notifier.ko",
        "drivers/virt/gunyah/gh_msgq.ko",
        "drivers/virt/gunyah/gh_panic_notifier.ko",
        "drivers/virt/gunyah/gh_rm_booster.ko",
        "drivers/virt/gunyah/gh_rm_drv.ko",
        "drivers/virt/gunyah/gh_virt_wdt.ko",
        "drivers/virt/gunyah/gunyah_loader.ko",
        "kernel/msm_sysstats.ko",
        "kernel/sched/walt/sched-walt.ko",
        "kernel/trace/qcom_ipc_logging.ko",
        "net/mac80211/mac80211.ko",
        "mm/zsmalloc.ko",
        "net/qrtr/qrtr.ko",
        "net/qrtr/qrtr-gunyah.ko",
        "net/qrtr/qrtr-mhi.ko",
        "net/qrtr/qrtr-smd.ko",
        "net/qrtr/qrtr-tun.ko",
        "net/wireless/cfg80211.ko",
        "sound/soc/codecs/snd-soc-hdmi-codec.ko",
        "sound/usb/snd-usb-audio-qmi.ko",
        "lib/kunit/kunit.ko",
        "drivers/base/regmap/regmap-kunit.ko",
        "drivers/base/regmap/regmap-ram.ko",
        "drivers/base/regmap/regmap-raw-ram.ko",
    ]

    _sun_consolidate_in_tree_modules = _sun_in_tree_modules + [
        # keep sorted
        "drivers/cpuidle/governors/qcom_simple_lpm.ko",
        "drivers/hwtracing/coresight/coresight-etm4x.ko",
        "drivers/misc/lkdtm/lkdtm.ko",
        "kernel/locking/locktorture.ko",
        "kernel/rcu/rcutorture.ko",
        "kernel/sched/walt/sched-walt-debug.ko",
        "kernel/torture.ko",
        "lib/atomic64_test.ko",
        "lib/test_user_copy.ko",
    ]

    kernel_vendor_cmdline_extras = ["bootconfig"]

    for variant in la_variants:
        board_kernel_cmdline_extras = []
        board_bootconfig_extras = []

        if variant == "consolidate":
            mod_list = _sun_consolidate_in_tree_modules
            board_bootconfig_extras += ["androidboot.serialconsole=1"]
            board_kernel_cmdline_extras += [
                # do not sort
                "console=ttyMSM0,115200n8",
                "qcom_geni_serial.con_enabled=1",
                "earlycon",
                "ufshcd_core.uic_cmd_timeout=2000",
            ]
            kernel_vendor_cmdline_extras += [
                # do not sort
                "console=ttyMSM0,115200n8",
                "qcom_geni_serial.con_enabled=1",
                "earlycon",
            ]
        else:
            mod_list = _sun_in_tree_modules
            board_kernel_cmdline_extras += ["nosoftlockup console=ttynull qcom_geni_serial.con_enabled=0"]
            kernel_vendor_cmdline_extras += ["nosoftlockup console=ttynull qcom_geni_serial.con_enabled=0"]
            board_bootconfig_extras += ["androidboot.serialconsole=0"]

        mod_list = mod_list + sec_bsp(
            target = target_name,
            variant = variant
        )

        mod_list = mod_list + kunit_module_list
        mod_list = mod_list + lego_module_list

        mod_list = mod_list + sec_block(
            target = target_name,
            variant = variant
        )

        mod_list = mod_list + sec_usb(
            target = target_name,
            variant = variant
        )
        mod_list = mod_list + sec_sensor(
            target = target_name,
            variant = variant
        )

        mod_list = mod_list + sec_audio(
            target = target_name,
            variant = variant
        )

        mod_list = mod_list + sec_power(
            target = target_name,
            variant = variant
        )

        mod_list = mod_list + sec_mm()

        mod_list = mod_list + sec_ipc(
            target = target_name,
            variant = variant
        )

        define_msm_la(
            msm_target = target_name,
            variant = variant,
            in_tree_module_list = remove_unused_modules_by_sec(
                mod_list = mod_list
            ),
            boot_image_opts = boot_image_opts(
                earlycon_addr = "qcom_geni,0x00a9c000",
                kernel_vendor_cmdline_extras = kernel_vendor_cmdline_extras,
                board_kernel_cmdline_extras = board_kernel_cmdline_extras,
                board_bootconfig_extras = board_bootconfig_extras,
            ),
        )

def remove_unused_modules_by_sec(mod_list):
    _mod_list = []
    _sec_blocked_modules = [
        # keep sorted
        "drivers/soc/qcom/qcom_logbuf_boot_log.ko",
        "drivers/soc/qcom/qcom_logbuf_vendor_hooks.ko",
    ]

    for mod in mod_list:
        if not mod in _sec_blocked_modules:
            _mod_list = _mod_list + [ mod ]

    return _mod_list
