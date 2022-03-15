if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2062.1" );
	script_cve_id( "CVE-2014-3688" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:42 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-08-23 02:08:00 +0000 (Tue, 23 Aug 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2062-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2062-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182062-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2062-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2014-3688: The SCTP implementation allowed remote attackers to cause
 a denial of service (memory consumption) by triggering a large number of
 chunks in an association's output queue (bsc#902351).
The following non-security bugs were fixed:
- ALSA: hda/ca0132: fix build failure when a local macro is defined
 (bsc#1045538).
- ALSA: seq: Do not allow resizing pool in use (bsc#1045538).
- Delete
 patches.fixes/0001-ipc-shm-Fix-shmat-mmap-nil-page-protection.patch
 (bsc# 1090078)
- IB/mlx4: fix sprintf format warning (bnc#786036).
- RDMA/mlx4: Discard unknown SQP work requests (bnc#786036).
- USB: uss720: fix NULL-deref at probe (bnc#1047487).
- bna: integer overflow bug in debugfs (bnc#780242).
- e1000e: Ignore TSYNCRXCTL when getting I219 clock attributes
 (bug#923242).
- e1000e: Undo e1000e_pm_freeze if __e1000_shutdown fails (bug#909495).
- fix a leak in /proc/schedstats (bsc#1094876).
- ixgbe: Initialize 64-bit stats seqcounts (bnc#795301).
- mm: fix the NULL mapping case in __isolate_lru_page() (git-fixes).
- module/retpoline: Warn about missing retpoline in module (bnc#1099177).
- net/mlx4_core: Fix error handling in mlx4_init_port_info (bnc#786036).
- net/mlx4_en: Change default QoS settings (bnc#786036 ).
- net/mlx4_en: Use __force to fix a sparse warning in TX datapath
 (bug#925105).
- netxen: fix incorrect loop counter decrement (bnc#784815).
- powerpc: Machine check interrupt is a non-maskable interrupt
 (bsc#1094244).
- s390/qdio: do not merge ERROR output buffers (bnc#1099709).
- s390/qeth: do not dump control cmd twice (bnc#1099709).
- s390/qeth: fix SETIP command handling (bnc#1099709).
- s390/qeth: free netdevice when removing a card (bnc#1099709).
- s390/qeth: lock read device while queueing next buffer (bnc#1099709).
- s390/qeth: when thread completes, wake up all waiters (bnc#1099709).
- sched/sysctl: Check user input value of sysctl_sched_time_avg
 (bsc#1100089).
- scsi: sg: mitigate read/write abuse (bsc#1101296).
- tg3: do not clear stats while tg3_close (bnc#790588).
- video/stifb: Return -ENOMEM after a failed kzalloc() in stifb_init_fb()
 (bnc#1099966).
- vmxnet3: use correct flag to indicate LRO feature (bsc#936423).
- x86-32/kaiser: Add CPL check for CR3 switch before iret (bsc#1098408).
- x86-non-upstream-eager-fpu 32bit fix (bnc#1087086, bnc#1100091,
 bnc#1099598).
- x86/cpu/bugs: Make retpoline module warning conditional (bnc#1099177)." );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra", rpm: "kernel-default-extra~3.0.101~108.60.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-extra", rpm: "kernel-pae-extra~3.0.101~108.60.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-extra", rpm: "kernel-ppc64-extra~3.0.101~108.60.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-extra", rpm: "kernel-trace-extra~3.0.101~108.60.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-extra", rpm: "kernel-xen-extra~3.0.101~108.60.1", rls: "SLES11.0" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem", rpm: "kernel-bigmem~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem-base", rpm: "kernel-bigmem-base~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem-devel", rpm: "kernel-bigmem-devel~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64", rpm: "kernel-ppc64~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-base", rpm: "kernel-ppc64-base~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-devel", rpm: "kernel-ppc64-devel~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace", rpm: "kernel-trace~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-base", rpm: "kernel-trace-base~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-devel", rpm: "kernel-trace-devel~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.0.101~108.60.1", rls: "SLES11.0SP4" ) )){
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

