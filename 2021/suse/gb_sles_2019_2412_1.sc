if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2412.1" );
	script_cve_id( "CVE-2017-18551", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-10207", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15090", "CVE-2019-15098", "CVE-2019-15099", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15222", "CVE-2019-15239", "CVE-2019-15290", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15902", "CVE-2019-15917", "CVE-2019-15919", "CVE-2019-15920", "CVE-2019-15921", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-9456" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-03 00:15:00 +0000 (Tue, 03 Sep 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2412-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2412-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192412-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2412-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following new features were implemented:
jsc#SLE-4875: [CML] New device IDs for CML

jsc#SLE-7294: Add cpufreq driver for Raspberry Pi

fate#322438: Integrate P9 XIVE support (on PowerVM only)

fate#322447: Add memory protection keys (MPK) support on POWER (on
 PowerVM only)

fate#322448, fate#321438: P9 hardware counter (performance counters)
 support (on PowerVM only)

fate#325306, fate#321840: Reduce memory required to boot capture kernel
 while using fadump

fate#326869: perf: pmu mem_load/store event support

The following security bugs were fixed:
CVE-2017-18551: There was an out of bounds write in the function
 i2c_smbus_xfer_emulated. (bsc#1146163).

CVE-2018-20976: A use after free existed, related to xfs_fs_fill_super
 failure. (bsc#1146285)

CVE-2018-21008: A use-after-free can be caused by the function
 rsi_mac80211_detach (bsc#1149591).

CVE-2019-9456: In Pixel C USB monitor driver there was a possible OOB
 write due to a missing bounds check. This could have lead to local
 escalation of privilege with System execution privileges needed.
 (bsc#1150025 CVE-2019-9456).

CVE-2019-10207: Fix a NULL pointer dereference in hci_uart bluetooth
 driver (bsc#1142857 bsc#1123959).

CVE-2019-14814, CVE-2019-14815, CVE-2019-14816: Fix three heap-based
 buffer overflows in marvell wifi chip driver kernel, that allowed local
 users to cause a denial of service (system crash) or possibly execute
 arbitrary code. (bnc#1146516)

CVE-2019-14835: Fix QEMU-KVM Guest to Host Kernel Escape. (bsc#1150112).

CVE-2019-15030, CVE-2019-15031: On the powerpc platform, a local user
 could read vector registers of other users' processes via an interrupt.
 (bsc#1149713)

CVE-2019-15090: In the qedi_dbg_* family of functions, there was an
 out-of-bounds read. (bsc#1146399)

CVE-2019-15098: USB driver net/wireless/ath/ath6kl/usb.c had a NULL
 pointer dereference via an incomplete address in an endpoint descriptor.
 (bsc#1146378).

CVE-2019-15099: drivers/net/wireless/ath/ath10k/usb.c had a NULL pointer
 dereference via an incomplete address in an endpoint descriptor.
 (bsc#1146368)

CVE-2019-15117: parse_audio_mixer_unit in sound/usb/mixer.c in the Linux
 kernel mishandled a short descriptor, leading to out-of-bounds memory
 access. (bsc#1145920).

CVE-2019-15118: check_input_term in sound/usb/mixer.c in the Linux
 kernel mishandled recursion, leading to kernel stack exhaustion.
 (bsc#1145922).

CVE-2019-15211: There was a use-after-free caused by a malicious USB
 device in the drivers/media/v4l2-core/v4l2-dev.c driver because
 drivers/media/radio/radio-raremono.c did not properly allocate memory.
 (bsc#1146519).

CVE-2019-15212: There was a double-free caused by a malicious USB device
 in the drivers/usb/misc/rio500.c driver. (bsc#1051510 bsc#1146391).

CVE-2019-15214: There was a ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~95.32.1", rls: "SLES12.0SP4" ) )){
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

