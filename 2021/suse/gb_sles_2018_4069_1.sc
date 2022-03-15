if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.4069.1" );
	script_cve_id( "CVE-2017-16533", "CVE-2017-18224", "CVE-2018-10940", "CVE-2018-16658", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18445", "CVE-2018-18710", "CVE-2018-19824" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:4069-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:4069-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20184069-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:4069-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-19824: A local user could exploit a use-after-free in the ALSA
 driver by supplying a malicious USB Sound device (with zero interfaces)
 that is mishandled in usb_audio_probe in sound/usb/card.c (bnc#1118152).

CVE-2018-18281: The mremap() syscall performs TLB flushes after dropping
 pagetable locks. If a syscall such as ftruncate() removed entries from
 the pagetables of a task that is in the middle of mremap(), a stale TLB
 entry could remain for a short time that permits access to a physical
 page after it has been released back to the page allocator and reused.
 (bnc#1113769).

CVE-2018-18710: An information leak in cdrom_ioctl_select_disc in
 drivers/cdrom/cdrom.c could be used by local attackers to read kernel
 memory because a cast from unsigned long to int interferes with bounds
 checking. This is similar to CVE-2018-10940 and CVE-2018-16658
 (bnc#1113751).

CVE-2018-18445: Faulty computation of numeric bounds in the BPF verifier
 permitted out-of-bounds memory accesses because
 adjust_scalar_min_max_vals in kernel/bpf/verifier.c mishandled 32-bit
 right shifts (bnc#1112372).

CVE-2018-18386: drivers/tty/n_tty.c allowed local attackers (who are
 able to access pseudo terminals) to hang/block further usage of any
 pseudo terminal devices due to an EXTPROC versus ICANON confusion in
 TIOCINQ (bnc#1094825).

CVE-2017-18224: fs/ocfs2/aops.c omitted use of a semaphore and
 consequently had a race condition for access to the extent tree during
 read operations in DIRECT mode, which allowed local users to cause a
 denial of service (BUG) by modifying a certain e_cpos field
 (bnc#1084831).

CVE-2017-16533: The usbhid_parse function in
 drivers/hid/usbhid/hid-core.c allowed local users to cause a denial of
 service (out-of-bounds read and system crash) or possibly have
 unspecified other impact via a crafted USB device (bnc#1066674).

The following non-security bugs were fixed:
ACPI/APEI: Handle GSIV and GPIO notification types (bsc#1115567).

ACPICA: Tables: Add WSMT support (bsc#1089350).

ACPI/IORT: Fix iort_get_platform_device_domain() uninitialized pointer
 value (bsc#1051510).

ACPI / LPSS: Add alternative ACPI HIDs for Cherry Trail DMA controllers
 (bsc#1051510).

ACPI, nfit: Fix ARS overflow continuation (bsc#1116895).

ACPI, nfit: Prefer _DSM over _LSR for namespace label reads
 (bsc#1112128).

ACPI/nfit, x86/mce: Handle only uncorrectable machine checks
 (bsc#1114279).

ACPI/nfit, x86/mce: Validate a MCE's address before using it
 (bsc#1114279).

ACPI / platform: Add SMB0001 HID to forbidden_id_list (bsc#1051510).

ACPI / processor: Fix the return value of acpi_processor_ids_walk()
 (bsc#1051510).

ACPI / watchdog: Prefer iTCO_wdt always when WDAT table uses RTC SRAM
 (bsc#1051510).

act_ife: fix a potential ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~95.3.1", rls: "SLES12.0SP4" ) )){
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

