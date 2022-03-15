if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3281.1" );
	script_cve_id( "CVE-2020-0430", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14351", "CVE-2020-16120", "CVE-2020-25212", "CVE-2020-25285", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-27673", "CVE-2020-27675" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-08 16:15:00 +0000 (Thu, 08 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3281-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3281-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203281-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3281-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 kernel Azure was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-25656: Fixed a concurrency use-after-free in vt_do_kdgkb_ioctl
 (bnc#1177766).

CVE-2020-25285: Fixed a race condition between hugetlb sysctl handlers
 in mm/hugetlb.c (bnc#1176485).

CVE-2020-0430: Fixed an OOB read in skb_headlen of
 /include/linux/skbuff.h (bnc#1176723).

CVE-2020-14351: Fixed a race in the perf_mmap_close() function
 (bsc#1177086).

CVE-2020-16120: Fixed a permissions issue in ovl_path_open()
 (bsc#1177470).

CVE-2020-12351: Implemented a kABI workaround for bluetooth l2cap_ops
 filter addition (bsc#1177724).

CVE-2020-12352: Fixed an information leak when processing certain AMP
 packets aka 'BleedingTooth' (bsc#1177725).

CVE-2020-25212: Fixed a TOCTOU mismatch in the NFS client code
 (bnc#1176381).

CVE-2020-25645: Fixed an issue in IPsec that caused traffic between
 two Geneve endpoints to be unencrypted (bnc#1177511).

CVE-2020-27673: Fixed an issue where rogue guests could have caused
 denial of service of Dom0 via high frequency events (XSA-332 bsc#1177411)

CVE-2020-27675: Fixed a race condition in event handler which may crash
 dom0 (XSA-331 bsc#1177410).

The following non-security bugs were fixed:

ACPI: dock: fix enum-conversion warning (git-fixes).

ALSA: bebob: potential info leak in hwdep_read() (git-fixes).

ALSA: compress_offload: remove redundant initialization (git-fixes).

ALSA: core: init: use DECLARE_COMPLETION_ONSTACK() macro (git-fixes).

ALSA: core: pcm: simplify locking for timers (git-fixes).

ALSA: core: timer: clarify operator precedence (git-fixes).

ALSA: core: timer: remove redundant assignment (git-fixes).

ALSA: ctl: Workaround for lockdep warning wrt card->ctl_files_rwlock
 (git-fixes).

ALSA: hda: auto_parser: remove shadowed variable declaration (git-fixes).

ALSA: hda - Do not register a cb func if it is registered already
 (git-fixes).

ALSA: hda/realtek - Add mute Led support for HP Elitebook 845 G7
 (git-fixes).

ALSA: hda/realtek: Enable audio jacks of ASUS D700SA with ALC887
 (git-fixes).

ALSA: hda/realtek - The front Mic on a HP machine does not work
 (git-fixes).

ALSA: hda: use semicolons rather than commas to separate statements
 (git-fixes).

ALSA: mixart: Correct comment wrt obsoleted tasklet usage (git-fixes).

ALSA: rawmidi: (cosmetic) align function parameters (git-fixes).

ALSA: seq: oss: Avoid mutex lock for a long-time ioctl (git-fixes).

ALSA: usb-audio: Add mixer support for Pioneer DJ DJM-250MK2 (git-fixes).

ALSA: usb-audio: endpoint.c: fix repeated word 'there' (git-fixes).

ALSA: usb-audio: fix spelling mistake 'Frequence' -> 'Frequency'
 (git-fixes).

amd-xgbe: Add a check for an skb in the timestamp path (git-fixes).

amd-xgbe: Add additional dynamic debug messages (git-fixes).

amd-xgbe: Add additional ethtool statistics ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~16.34.1", rls: "SLES12.0SP5" ) )){
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

