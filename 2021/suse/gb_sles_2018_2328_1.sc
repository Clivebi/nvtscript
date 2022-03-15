if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2328.1" );
	script_cve_id( "CVE-2017-18344", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 17:29:00 +0000 (Tue, 23 Apr 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2328-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2328-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182328-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2328-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.143 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-5390 aka 'SegmentSmack': Linux kernel could be forced to make
 very expensive calls to tcp_collapse_ofo_queue() and
 tcp_prune_ofo_queue() for every incoming packet which can lead to a
 denial of service (bnc#1102340).
- CVE-2018-14734: drivers/infiniband/core/ucma.c in the Linux kernel
 allowed ucma_leave_multicast to access a certain data structure after a
 cleanup step in ucma_process_join, which allowed attackers to cause a
 denial of service (use-after-free) (bnc#1103119).
- CVE-2017-18344: The timer_create syscall implementation in
 kernel/time/posix-timers.c didn't properly validate the
 sigevent->sigev_notify field, which lead to out-of-bounds access in the
 show_timer function (called when /proc/$PID/timers is read). This
 allowed userspace applications to read arbitrary kernel memory (on a
 kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE)
 (bnc#1102851 bnc#1103580).
- CVE-2018-3620: Local attackers on baremetal systems could use
 speculative code patterns on hyperthreaded processors to read data
 present in the L1 Datacache used by other hyperthreads on the same CPU
 core, potentially leaking sensitive data. (bnc#1087081).
- CVE-2018-3646: Local attackers in virtualized guest systems could use
 speculative code patterns on hyperthreaded processors to read data
 present in the L1 Datacache used by other hyperthreads on the same CPU
 core, potentially leaking sensitive data, even from other virtual
 machines or the host system. (bnc#1089343).
The following non-security bugs were fixed:
- Add support for 5,25,50, and 100G to 802.3ad bonding driver (bsc#1096978)
- ahci: Disable LPM on Lenovo 50 series laptops with a too old BIOS
 (bnc#1012382).
- arm64: do not open code page table entry creation (bsc#1102197).
- arm64: kpti: Use early_param for kpti= command-line option (bsc#1102188).
- arm64: Make sure permission updates happen for pmd/pud (bsc#1102197).
- atm: zatm: Fix potential Spectre v1 (bnc#1012382).
- bcm63xx_enet: correct clock usage (bnc#1012382).
- bcm63xx_enet: do not write to random DMA channel on BCM6345
 (bnc#1012382).
- blacklist 9fb8d5dc4b64 ('stop_machine: Disable preemption when waking
 two stopper threads') Preemption is already disabled inside
 cpu_stop_queue_two_works() in SLE12-SP3 because it does not have commit
 6a19005157c4 ('stop_machine: Do not disable preemption in
 stop_two_cpus()')
- block: copy ioprio in __bio_clone_fast() (bsc#1082653).
- bpf: fix loading of BPF_MAXINSNS sized programs (bsc#1012382).
- bpf, x64: fix memleak when not converging after image (bsc#1012382).
- cachefiles: Fix missing clear of the CACHEFILES_OBJECT_ACTIVE flag
 (bsc#1099858).
- cachefiles: Fix refcounting bug in backing-file read monitoring
 (bsc#1099858).
- cachefiles: Wait rather ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Live Patching 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~16.11.6~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~16.11.6~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~16.11.6~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~16.11.6_k4.4.143_94.47~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~16.11.6_k4.4.143_94.47~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx", rpm: "dpdk-thunderx~16.11.6~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debuginfo", rpm: "dpdk-thunderx-debuginfo~16.11.6~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debugsource", rpm: "dpdk-thunderx-debugsource~16.11.6~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default", rpm: "dpdk-thunderx-kmp-default~16.11.6_k4.4.143_94.47~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default-debuginfo", rpm: "dpdk-thunderx-kmp-default-debuginfo~16.11.6_k4.4.143_94.47~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~16.11.6~8.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.143~94.47.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules", rpm: "lttng-modules~2.7.1~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-debugsource", rpm: "lttng-modules-debugsource~2.7.1~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-kmp-default", rpm: "lttng-modules-kmp-default~2.7.1_k4.4.143_94.47~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-kmp-default-debuginfo", rpm: "lttng-modules-kmp-default-debuginfo~2.7.1_k4.4.143_94.47~8.4.2", rls: "SLES12.0SP3" ) )){
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

