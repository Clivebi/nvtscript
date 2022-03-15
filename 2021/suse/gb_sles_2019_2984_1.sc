if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2984.1" );
	script_cve_id( "CVE-2016-10906", "CVE-2017-18509", "CVE-2017-18595", "CVE-2018-12207", "CVE-2018-20976", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-13272", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15098", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15290", "CVE-2019-15291", "CVE-2019-15505", "CVE-2019-15666", "CVE-2019-15807", "CVE-2019-15902", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-16231", "CVE-2019-16232", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16413", "CVE-2019-16995", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-18680", "CVE-2019-18805", "CVE-2019-9456", "CVE-2019-9506" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-04 05:15:00 +0000 (Wed, 04 Sep 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2984-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2984-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192984-1/" );
	script_xref( name: "URL", value: "https://www.suse.com/support/kb/doc/?id=7023735" );
	script_xref( name: "URL", value: "https://www.suse.com/support/kb/doc/?id=7024251" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2984-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-12207: Untrusted virtual machines on Intel CPUs could exploit a
 race condition in the Instruction Fetch Unit of the Intel CPU to cause a
 Machine Exception during Page Size Change, causing the CPU core to be
 non-functional.

 The Linux Kernel kvm hypervisor was adjusted to avoid page size changes in executable pages by splitting / merging huge pages into small pages as needed. More information can be found on [link moved to references] CVE-2019-16995: Fix a memory leak in hsr_dev_finalize() if hsr_add_port
 failed to add a port, which may have caused denial of service
 (bsc#1152685).
CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs
 with Transactional Memory support could be used to facilitate
 sidechannel information leaks out of microarchitectural buffers, similar
 to the previously described 'Microarchitectural Data Sampling' attack.

 The Linux kernel was supplemented with the option to disable TSX operation altogether (requiring CPU Microcode updates on older systems)
and better flushing of microarchitectural buffers (VERW).

 The set of options available is described in our TID at [link moved to references] CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the
 alloc_workqueue return value, leading to a NULL pointer dereference.
 (bsc#1150457).
CVE-2019-10220: Added sanity checks on the pathnames passed to the user
 space. (bsc#1144903).
CVE-2019-17666: rtlwifi: Fix potential overflow in P2P code
 (bsc#1154372).
CVE-2019-17133: cfg80211 wireless extension did not reject a long SSID
 IE, leading to a Buffer Overflow (bsc#1153158).
CVE-2019-16232: Fix a potential NULL pointer dereference in the Marwell
 libertas driver (bsc#1150465).
CVE-2019-16234: iwlwifi pcie driver did not check the alloc_workqueue
 return value, leading to a NULL pointer dereference. (bsc#1150452).
CVE-2019-17055: The AF_ISDN network module in the Linux kernel did not
 enforce CAP_NET_RAW, which meant that unprivileged users could create a
 raw socket (bnc#1152782).
CVE-2019-17056: The AF_NFC network module did not enforce CAP_NET_RAW,
 which meant that unprivileged users could create a raw socket
 (bsc#1152788).
CVE-2019-16413: The 9p filesystem did not protect i_size_write()
 properly, which caused an i_size_read() infinite loop and denial of
 service on SMP systems (bnc#1151347).
CVE-2019-15902: A backporting issue was discovered that re-introduced
 the Spectre vulnerability it had aimed to eliminate. This occurred
 because the backport process depends on cherry picking specific commits,
 and because two (correctly ordered) code lines were swapped
 (bnc#1149376).
CVE-2019-15291: Fixed a NULL pointer dereference issue that could be
 caused by a malicious USB device ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.121~92.125.1", rls: "SLES12.0SP2" ) )){
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

