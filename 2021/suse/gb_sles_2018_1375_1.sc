if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1375.1" );
	script_cve_id( "CVE-2018-1000199", "CVE-2018-10675", "CVE-2018-3639" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1375-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1375-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181375-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1375-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP1 LTSS kernel was updated to receive various security and bugfixes.
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
- CVE-2018-1000199: An address corruption flaw was discovered while
 modifying a h/w breakpoint via 'modify_user_hw_breakpoint' routine, an
 unprivileged user/process could use this flaw to crash the system kernel
 resulting in DoS OR to potentially escalate privileges on a the system.
 (bsc#1089895)
- CVE-2018-10675: The do_get_mempolicy function in mm/mempolicy.c allowed
 local users to cause a denial of service (use-after-free) or possibly
 have unspecified other impact via crafted system calls (bnc#1091755).
The following non-security bugs were fixed:
- x86/bugs: Make sure that _TIF_SSBD does not end up in _TIF_ALLWORK_MASK
 (bsc#1093215).
- x86/bugs: correctly force-disable IBRS on !SKL systems (bsc#1092497).
- x86/cpu/intel: Introduce macros for Intel family numbers (bsc#985025).
- x86/speculation: Remove Skylake C2 from Speculation Control microcode
 blacklist (bsc#1087845)." );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.12.74~60.64.93.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.12.74~60.64.93.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.12.74~60.64.93.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.12.74~60.64.93.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra", rpm: "kernel-ec2-extra~3.12.74~60.64.93.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra-debuginfo", rpm: "kernel-ec2-extra-debuginfo~3.12.74~60.64.93.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.74~60.64.93.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_93-default", rpm: "kgraft-patch-3_12_74-60_64_93-default~1~2.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_93-xen", rpm: "kgraft-patch-3_12_74-60_64_93-xen~1~2.5.1", rls: "SLES12.0SP1" ) )){
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

