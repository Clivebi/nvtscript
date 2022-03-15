if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2879.1" );
	script_cve_id( "CVE-2017-18595", "CVE-2019-14821", "CVE-2019-15291", "CVE-2019-16232", "CVE-2019-16234", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-9506" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2879-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2879-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192879-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2879-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2017-18595: A double free may be caused by the function
 allocate_trace_buffer in the file kernel/trace/trace.c (bnc#1149555).

CVE-2019-14821: An out-of-bounds access issue was found in the way Linux
 kernel's KVM hypervisor implements the coalesced MMIO write operation.
 It operates on an MMIO ring buffer 'struct kvm_coalesced_mmio' object,
 wherein write indices 'ring->first' and 'ring->last' value could be
 supplied by a host user-space process. An unprivileged host user or
 process with access to '/dev/kvm' device could use this flaw to crash
 the host kernel, resulting in a denial of service or potentially
 escalating privileges on the system (bnc#1151350).

CVE-2019-15291: There was a NULL pointer dereference caused by a
 malicious USB device in the flexcop_usb_probe function in the
 drivers/media/usb/b2c2/flexcop-usb.c driver (bnc#1146540).

CVE-2019-9506: The Bluetooth BR/EDR specification up to and including
 version 5.1 permitted sufficiently low encryption key length and did not
 prevent an attacker from influencing the key length negotiation. This
 allowed practical brute-force attacks (aka 'KNOB') that could decrypt
 traffic and injected arbitrary ciphertext without the victim noticing
 (bnc#1137865 bnc#1146042).

CVE-2019-16232: Fixed a NULL pointer dereference in
 drivers/net/wireless/marvell/libertas/if_sdio.c, which did not check the
 alloc_workqueue return value (bnc#1150465).

CVE-2019-16234: Fixed a NULL pointer dereference in
 drivers/net/wireless/intel/iwlwifi/pcie/trans.c, which did not check the
 alloc_workqueue return value (bnc#1150452).

CVE-2019-17056: Added enforcement of CAP_NET_RAW in llcp_sock_create in
 net/nfc/llcp_sock.c in the AF_NFC network module, the lack of which
 allowed unprivileged users to create a raw socket, aka CID-3a359798b176
 (bnc#1152788).

CVE-2019-17133: Fixed a buffer overflow in cfg80211_mgd_wext_giwessid in
 net/wireless/wext-sme.c caused by long SSID IEs (bsc#1153158).

CVE-2019-17666: Added an upper-bound check in rtl_p2p_noa_ie in
 drivers/net/wireless/realtek/rtlwifi/ps.c, the lack of which could have
 led to a buffer overflow (bnc#1154372).

The following non-security bugs were fixed:
9p: avoid attaching writeback_fid on mmap with type PRIVATE
 (bsc#1051510).

ACPI / CPPC: do not require the _PSD method (bsc#1051510).

ACPI: CPPC: Set pcc_data[pcc_ss_id] to NULL in
 acpi_cppc_processor_exit() (bsc#1051510).

ACPI: custom_method: fix memory leaks (bsc#1051510).

ACPI / PCI: fix acpi_pci_irq_enable() memory leak (bsc#1051510).

ACPI / processor: do not print errors for processorIDs == 0xff
 (bsc#1051510).

ACPI / property: Fix acpi_graph_get_remote_endpoint() name in kerneldoc
 (bsc#1051510).

act_mirred: Fix mirred_init_module error handling (bsc#1051510).

Add kernel module ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP4." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~95.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

