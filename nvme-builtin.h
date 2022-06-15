/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE nvme-builtin

#if !defined(NVME_BUILTIN) || defined(CMD_HEADER_MULTI_READ)
#define NVME_BUILTIN

#include "cmd.h"

COMMAND_LIST(
	ENTRY("list", "List all NVMe devices and namespaces on machine", list)
	ENTRY("list-subsys", "List nvme subsystems", list_subsys)
	ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
	ENTRY("id-ns", "Send NVMe Identify Namespace, display structure", id_ns)
	ENTRY("id-ns-granularity", "Send NVMe Identify Namespace Granularity List, display structure", id_ns_granularity)
	ENTRY("id-ns-lba-format", "Send NVMe Identify Namespace for the specified LBA Format index, display structure", id_ns_lba_format)
	ENTRY("list-ns", "Send NVMe Identify List, display structure", list_ns)
	ENTRY("list-ctrl", "Send NVMe Identify Controller List, display structure", list_ctrl)
	ENTRY("nvm-id-ctrl", "Send NVMe Identify Controller NVM Command Set, display structure", nvm_id_ctrl)
	ENTRY("nvm-id-ns", "Send NVMe Identify Namespace NVM Command Set, display structure", nvm_id_ns)
	ENTRY("nvm-id-ns-lba-format", "Send NVMe Identify Namespace NVM Command Set for the specified LBA Format index, display structure", nvm_id_ns_lba_format)
	ENTRY("primary-ctrl-caps", "Send NVMe Identify Primary Controller Capabilities", primary_ctrl_caps)
	ENTRY("list-secondary", "List Secondary Controllers associated with a Primary Controller", list_secondary_ctrl)
	ENTRY("cmdset-ind-id-ns", "I/O Command Set Independent Identify Namespace", cmd_set_independent_id_ns)
	ENTRY("ns-descs", "Send NVMe Namespace Descriptor List, display structure", ns_descs)
	ENTRY("id-nvmset", "Send NVMe Identify NVM Set List, display structure", id_nvmset)
	ENTRY("id-uuid", "Send NVMe Identify UUID List, display structure", id_uuid)
	ENTRY("id-iocs", "Send NVMe Identify I/O Command Set, display structure", id_iocs)
	ENTRY("id-domain", "Send NVMe Identify Domain List, display structure", id_domain)
	ENTRY("list-endgrp", "Send NVMe Identify Endurance Group List, display structure", id_endurance_grp_list)
	ENTRY("create-ns", "Creates a namespace with the provided parameters", create_ns)
	ENTRY("delete-ns", "Deletes a namespace from the controller", delete_ns)
	ENTRY("attach-ns", "Attaches a namespace to requested controller(s)", attach_ns)
	ENTRY("detach-ns", "Detaches a namespace from requested controller(s)", detach_ns)
	ENTRY("get-ns-id", "Retrieve the namespace ID of opened block device", get_ns_id)
	ENTRY("get-log", "Generic NVMe get log, returns log in raw format", get_log)
	ENTRY("telemetry-log", "Retrieve FW Telemetry log write to file", get_telemetry_log)
	ENTRY("fw-log", "Retrieve FW Log, show it", get_fw_log)
	ENTRY("changed-ns-list-log", "Retrieve Changed Namespace List, show it", get_changed_ns_list_log)
	ENTRY("smart-log", "Retrieve SMART Log, show it", get_smart_log)
	ENTRY("ana-log", "Retrieve ANA Log, show it", get_ana_log)
	ENTRY("error-log", "Retrieve Error Log, show it", get_error_log)
	ENTRY("effects-log", "Retrieve Command Effects Log, show it", get_effects_log)
	ENTRY("endurance-log", "Retrieve Endurance Group Log, show it", get_endurance_log)
	ENTRY("predictable-lat-log", "Retrieve Predictable Latency per Nvmset Log, show it", get_pred_lat_per_nvmset_log)
	ENTRY("pred-lat-event-agg-log", "Retrieve Predictable Latency Event Aggregate Log, show it", get_pred_lat_event_agg_log)
	ENTRY("persistent-event-log", "Retrieve Presistent Event Log, show it", get_persistent_event_log)
	ENTRY("endurance-event-agg-log", "Retrieve Endurance Group Event Aggregate Log, show it", get_endurance_event_agg_log)
	ENTRY("lba-status-log", "Retrieve LBA Status Information Log, show it", get_lba_status_log)
	ENTRY("resv-notif-log", "Retrieve Reservation Notification Log, show it", get_resv_notif_log)
	ENTRY("boot-part-log", "Retrieve Boot Partition Log, show it", get_boot_part_log)
	ENTRY("get-feature", "Get feature and show the resulting value", get_feature)
	ENTRY("device-self-test", "Perform the necessary tests to observe the performance", device_self_test)
	ENTRY("self-test-log", "Retrieve the SELF-TEST Log, show it", self_test_log)
	ENTRY("supported-log-pages", "Retrieve the Supported Log pages details, show it", get_supported_log_pages)
	ENTRY("fid-support-effects-log", "Retrieve FID Support and Effects log and show it", get_fid_support_effects_log)
	ENTRY("mi-cmd-support-effects-log", "Retrieve MI Command Support and Effects log and show it", get_mi_cmd_support_effects_log)
	ENTRY("media-unit-stat-log", "Retrieve the configuration and wear of media units, show it", get_media_unit_stat_log)
	ENTRY("supported-cap-config-log", "Retrieve the list of Supported Capacity Configuration Descriptors", get_supp_cap_config_log)
	ENTRY("set-feature", "Set a feature and show the resulting value", set_feature)
	ENTRY("set-property", "Set a property and show the resulting value", set_property)
	ENTRY("get-property", "Get a property and show the resulting value", get_property)
	ENTRY("format", "Format namespace with new block format", format)
	ENTRY("fw-commit", "Verify and commit firmware to a specific slot (fw-activate in old version < 1.2)", fw_commit, "fw-activate")
	ENTRY("fw-download", "Download new firmware", fw_download)
	ENTRY("admin-passthru", "Submit an arbitrary admin command, return results", admin_passthru)
	ENTRY("io-passthru", "Submit an arbitrary IO command, return results", io_passthru)
	ENTRY("security-send", "Submit a Security Send command, return results", sec_send)
	ENTRY("security-recv", "Submit a Security Receive command, return results", sec_recv)
	ENTRY("get-lba-status", "Submit a Get LBA Status command, return results", get_lba_status)
	ENTRY("capacity-mgmt", "Submit Capacity Management Command, return results", capacity_mgmt)
	ENTRY("resv-acquire", "Submit a Reservation Acquire, return results", resv_acquire)
	ENTRY("resv-register", "Submit a Reservation Register, return results", resv_register)
	ENTRY("resv-release", "Submit a Reservation Release, return results", resv_release)
	ENTRY("resv-report", "Submit a Reservation Report, return results", resv_report)
	ENTRY("dsm", "Submit a Data Set Management command, return results", dsm)
	ENTRY("copy", "Submit a Simple Copy command, return results", copy)
	ENTRY("flush", "Submit a Flush command, return results", flush)
	ENTRY("compare", "Submit a Compare command, return results", compare)
	ENTRY("read", "Submit a read command, return results", read_cmd)
	ENTRY("write", "Submit a write command, return results", write_cmd)
	ENTRY("write-zeroes", "Submit a write zeroes command, return results", write_zeroes)
	ENTRY("write-uncor", "Submit a write uncorrectable command, return results", write_uncor)
	ENTRY("verify", "Submit a verify command, return results", verify_cmd)
	ENTRY("sanitize", "Submit a sanitize command", sanitize)
	ENTRY("sanitize-log", "Retrieve sanitize log, show it", sanitize_log)
	ENTRY("reset", "Resets the controller", reset)
	ENTRY("subsystem-reset", "Resets the subsystem", subsystem_reset)
	ENTRY("ns-rescan", "Rescans the NVME namespaces", ns_rescan)
	ENTRY("show-regs", "Shows the controller registers or properties. Requires character device", show_registers)
	ENTRY("discover", "Discover NVMeoF subsystems", discover_cmd)
	ENTRY("connect-all", "Discover and Connect to NVMeoF subsystems", connect_all_cmd)
	ENTRY("connect", "Connect to NVMeoF subsystem", connect_cmd)
	ENTRY("disconnect", "Disconnect from NVMeoF subsystem", disconnect_cmd)
	ENTRY("disconnect-all", "Disconnect from all connected NVMeoF subsystems", disconnect_all_cmd)
	ENTRY("config", "Configuration of NVMeoF subsystems", config_cmd)
	ENTRY("gen-hostnqn", "Generate NVMeoF host NQN", gen_hostnqn_cmd)
	ENTRY("show-hostnqn", "Show NVMeoF host NQN", show_hostnqn_cmd)
	ENTRY("gen-dhchap-key", "Generate NVMeoF DH-HMAC-CHAP host key", gen_dhchap_key)
	ENTRY("check-dhchap-key", "Validate NVMeoF DH-HMAC-CHAP host key", check_dhchap_key)
	ENTRY("gen-tls-key", "Generate NVMeoF TLS PSK", gen_tls_key)
	ENTRY("check-tls-key", "Validate NVMeoF TLS PSK", check_tls_key)
	ENTRY("dir-receive", "Submit a Directive Receive command, return results", dir_receive)
	ENTRY("dir-send", "Submit a Directive Send command, return results", dir_send)
	ENTRY("virt-mgmt", "Manage Flexible Resources between Primary and Secondary Controller ", virtual_mgmt)
	ENTRY("rpmb", "Replay Protection Memory Block commands", rpmb_cmd)
	ENTRY("lockdown", "Submit a Lockdown command,return result", lockdown_cmd)
	ENTRY("dim", "Send Discovery Information Management command to a Discovery Controller", dim_cmd)
	ENTRY("show-topology", "Show the topology", show_topology_cmd) \
	ENTRY("connect-nbft", "Connect subsystems listed in ACPI NBFT tables", connect_nbft_cmd)
	ENTRY("show-nbft", "Show ACPI NBFT table contents", show_nbft_cmd)
);

#endif

#include "define_cmd.h"
