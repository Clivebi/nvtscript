if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1366.1" );
	script_cve_id( "CVE-2018-1000199", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1065", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803", "CVE-2018-7492", "CVE-2018-8781" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-28 01:03:00 +0000 (Thu, 28 Feb 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1366-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1366-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181366-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1366-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.131 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-3639: Information leaks using 'Memory Disambiguation' feature
 in modern CPUs were mitigated, aka 'Spectre Variant 4' (bnc#1087082).
 A new boot commandline option was introduced,
'spec_store_bypass_disable', which can have following values:
 - auto: Kernel detects whether your CPU model contains an implementation
 of Speculative Store Bypass and picks the most appropriate mitigation.
 - on: disable Speculative Store Bypass
 - off: enable Speculative Store Bypass
 - prctl: Control Speculative Store Bypass per thread via prctl.
 Speculative Store Bypass is enabled for a process by default. The
 state of the control is inherited on fork.
 - seccomp: Same as 'prctl' above, but all seccomp threads will disable
 SSB unless they explicitly opt out.
 The default is 'seccomp', meaning programs need explicit opt-in into the mitigation.
 Status can be queried via the
/sys/devices/system/cpu/vulnerabilities/spec_store_bypass file, containing:
 - 'Vulnerable'
 - 'Mitigation: Speculative Store Bypass disabled'
 - 'Mitigation: Speculative Store Bypass disabled via prctl'
 - 'Mitigation: Speculative Store Bypass disabled via prctl and seccomp'
- CVE-2018-8781: The udl_fb_mmap function in drivers/gpu/drm/udl/udl_fb.c
 had an integer-overflow vulnerability allowing local users with access
 to the udldrmfb driver to obtain full read and write permissions on
 kernel physical pages, resulting in a code execution in kernel space
 (bnc#1090643).
- CVE-2018-10124: The kill_something_info function in kernel/signal.c
 might have allowed local users to cause a denial of service via an
 INT_MIN argument (bnc#1089752).
- CVE-2018-10087: The kernel_wait4 function in kernel/exit.c might have
 allowed local users to cause a denial of service by triggering an
 attempted use of the -INT_MIN value (bnc#1089608).
- CVE-2018-1000199: An address corruption flaw was discovered while
 modifying a h/w breakpoint via 'modify_user_hw_breakpoint' routine, an
 unprivileged user/process could use this flaw to crash the system kernel
 resulting in DoS OR to potentially escalate privileges on a the system.
 (bsc#1089895)
- CVE-2018-1130: The Linux kernel was vulnerable to a null pointer
 dereference in dccp_write_xmit() function in net/dccp/output.c in that
 allowed a local user to cause a denial of service by a number of certain
 crafted system calls (bnc#1092904).
- CVE-2018-5803: An error in the _sctp_make_chunk() function when handling
 SCTP, packet length could have been exploited by a malicious local user
 to cause a kernel crash and a DoS. (bnc#1083900).
- CVE-2018-1065: The netfilter subsystem mishandled the case of a rule
 blob that contains a jump but lacks a user-defined chain, which allowed
 local users to cause a denial of service (NULL pointer ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Live Patching 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.131~94.29.1", rls: "SLES12.0SP3" ) )){
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

