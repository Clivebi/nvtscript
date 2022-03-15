if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1287.1" );
	script_cve_id( "CVE-2016-8636", "CVE-2017-17741", "CVE-2017-18174", "CVE-2018-1091", "CVE-2018-1120", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-19407", "CVE-2019-11091", "CVE-2019-11486", "CVE-2019-3882", "CVE-2019-8564", "CVE-2019-9503" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-21 11:29:00 +0000 (Fri, 21 Dec 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1287-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1287-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191287-1/" );
	script_xref( name: "URL", value: "https://www.suse.com/support/kb/doc/?id=7023736" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1287-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.

Four new speculative execution information leak issues have been identified in Intel CPUs. (bsc#1111331)
CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)

CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)

CVE-2018-12130: Microarchitectural Load Port Data Samling (MLPDS)

CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory
 (MDSUM)

This kernel update contains software mitigations for these issues, which also utilize CPU microcode updates shipped in parallel.

For more information on this set of information leaks, check out [link moved to references]

The following security bugs were fixed:
CVE-2018-1128: It was found that cephx authentication protocol did not
 verify ceph clients correctly and was vulnerable to replay attack. Any
 attacker having access to ceph cluster network who is able to sniff
 packets on network could use this vulnerability to authenticate with
 ceph service and perform actions allowed by ceph service. (bnc#1096748).

CVE-2018-1129: A flaw was found in the way signature calculation was
 handled by cephx authentication protocol. An attacker having access to
 ceph cluster network who is able to alter the message payload was able
 to bypass signature checks done by cephx protocol. (bnc#1096748).

CVE-2016-8636: Integer overflow in the mem_check_range function in
 drivers/infiniband/sw/rxe/rxe_mr.c allowed local users to cause a denial
 of service (memory corruption), obtain sensitive information or possibly
 have unspecified other impact via a write or read request involving the
 'RDMA protocol over infiniband' (aka Soft RoCE) technology (bnc#1024908).

CVE-2017-18174: In the amd_gpio_remove function in
 drivers/pinctrl/pinctrl-amd.c calls the pinctrl_unregister function,
 leading to a double free (bnc#1080533).

CVE-2018-1091: In the flush_tmregs_to_thread function in
 arch/powerpc/kernel/ptrace.c, a guest kernel crash can be triggered from
 unprivileged userspace during a core dump on a POWER host due to a
 missing processor feature check and an erroneous use of transactional
 memory (TM) instructions in the core dump path, leading to a denial of
 service (bnc#1087231).

CVE-2018-1120: By mmap()ing a FUSE-backed file onto a process's memory
 containing command line arguments (or environment strings), an attacker
 can cause utilities from psutils or procps (such as ps, w) or any other
 program which made a read() call to the /proc//cmdline (or
 /proc//environ) files to block indefinitely (denial of service) or
 for some controlled time (as a synchronization primitive for other
 attacks) (bnc#1093158).

CVE-2019-11486: The Siemens R3964 line discipline driver in
 drivers/tty/n_r3964.c has multiple race conditions (bnc#1133188).

CVE-2019-3882: A flaw was found in the vfio interface ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Enterprise Storage 4, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.121~92.109.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_109-default", rpm: "kgraft-patch-4_4_121-92_109-default~1~3.5.2", rls: "SLES12.0SP2" ) )){
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

