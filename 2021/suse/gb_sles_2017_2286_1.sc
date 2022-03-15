if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2286.1" );
	script_cve_id( "CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-10810", "CVE-2017-11473", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-8831" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2286-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2286-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172286-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2286-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.82 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2017-1000111: Fixed a race condition in net-packet code that could
 be exploited to cause out-of-bounds memory access (bsc#1052365).
- CVE-2017-1000112: Fixed a race condition in net-packet code that could
 have been exploited by unprivileged users to gain root access.
 (bsc#1052311).
- CVE-2017-8831: The saa7164_bus_get function in
 drivers/media/pci/saa7164/saa7164-bus.c in the Linux kernel allowed
 local users to cause a denial of service (out-of-bounds array access) or
 possibly have unspecified other impact by changing a certain
 sequence-number value, aka a 'double fetch' vulnerability (bnc#1037994).
- CVE-2017-7542: The ip6_find_1stfragopt function in
 net/ipv6/output_core.c in the Linux kernel allowed local users to cause
 a denial of service (integer overflow and infinite loop) by leveraging
 the ability to open a raw socket (bnc#1049882).
- CVE-2017-11473: Buffer overflow in the mp_override_legacy_irq() function
 in arch/x86/kernel/acpi/boot.c in the Linux kernel allowed local users
 to gain privileges via a crafted ACPI table (bnc#1049603).
- CVE-2017-7533: Race condition in the fsnotify implementation in the
 Linux kernel allowed local users to gain privileges or cause a denial of
 service (memory corruption) via a crafted application that leverages
 simultaneous execution of the inotify_handle_event and vfs_rename
 functions (bnc#1049483 bnc#1050677).
- CVE-2017-7541: The brcmf_cfg80211_mgmt_tx function in
 drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux
 kernel allowed local users to cause a denial of service (buffer overflow
 and system crash) or possibly gain privileges via a crafted
 NL80211_CMD_FRAME Netlink packet (bnc#1049645).
- CVE-2017-10810: Memory leak in the virtio_gpu_object_create function in
 drivers/gpu/drm/virtio/virtgpu_object.c in the Linux kernel allowed
 attackers to cause a denial of service (memory consumption) by
 triggering object-initialization failures (bnc#1047277).
The following non-security bugs were fixed:
- acpi/nfit: Add support of NVDIMM memory error notification in ACPI 6.2
 (bsc#1052325).
- acpi/nfit: Issue Start ARS to retrieve existing records (bsc#1052325).
- acpi / processor: Avoid reserving IO regions too early (bsc#1051478).
- acpi / scan: Prefer devices without _HID for _ADR matching (git-fixes).
- Add 'shutdown' to 'struct class' (bsc#1053117).
- af_key: Add lock to key dump (bsc#1047653).
- af_key: Fix slab-out-of-bounds in pfkey_compile_policy (bsc#1047354).
- alsa: fm801: Initialize chip after IRQ handler is registered
 (bsc#1031717).
- alsa: hda - add more ML register definitions (bsc#1048356).
- alsa: hda - add sanity check to force the separate stream tags
 (bsc#1048356).
- alsa: hda: Add support for parsing new HDA capabilities ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Live Patching 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.82~6.3.1", rls: "SLES12.0SP3" ) )){
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

