if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0040.1" );
	script_cve_id( "CVE-2017-1000251", "CVE-2017-11600", "CVE-2017-12192", "CVE-2017-13080", "CVE-2017-13167", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14340", "CVE-2017-15102", "CVE-2017-15115", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16534", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538", "CVE-2017-16649", "CVE-2017-16939", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-7472", "CVE-2017-8824" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0040-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0|SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0040-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180040-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0040-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated to receive various security and bugfixes.
This update adds mitigations for various side channel attacks against modern CPUs that could disclose content of otherwise unreadable memory
(bnc#1068032).
- CVE-2017-5753: Local attackers on systems with modern CPUs featuring
 deep instruction pipelining could use attacker controllable speculative
 execution over code patterns in the Linux Kernel to leak content from
 otherwise not readable memory in the same address space, allowing
 retrieval of passwords, cryptographic keys and other secrets.
 This problem is mitigated by adding speculative fencing on affected code paths throughout the Linux kernel.
- CVE-2017-5715: Local attackers on systems with modern CPUs featuring
 branch prediction could use mispredicted branches to speculatively
 execute code patterns that in turn could be made to leak other
 non-readable content in the same address space, an attack similar to
 CVE-2017-5753.
 This problem is mitigated by disabling predictive branches, depending
 on CPU architecture either by firmware updates and/or fixes in the
 user-kernel privilege boundaries.
 Please contact your CPU / hardware vendor for potential microcode
 or BIOS updates needed for this fix.
 As this feature can have a performance impact, it can be disabled using the 'nospec' kernel commandline option.
- CVE-2017-5754: Local attackers on systems with modern CPUs featuring
 deep instruction pipelining could use code patterns in userspace to
 speculative executive code that would read otherwise read protected
 memory, an attack similar to CVE-2017-5753.
 This problem is mitigated by unmapping the Linux Kernel from the user address space during user code execution, following a approach called
'KAISER'. The terms used here are 'KAISER' / 'Kernel Address Isolation'
and 'PTI' / 'Page Table Isolation'.
 This feature is disabled on unaffected architectures.
 This feature can be enabled / disabled by the 'pti=[on<pipe>off<pipe>auto]' or
'nopti' commandline options.
The following security bugs were fixed:
- CVE-2017-1000251: The native Bluetooth stack in the Linux Kernel (BlueZ)
 was vulnerable to a stack overflow vulnerability in the processing of
 L2CAP configuration responses resulting in Remote code execution in
 kernel space (bnc#1057389).
- CVE-2017-11600: net/xfrm/xfrm_policy.c in the Linux kernel did not
 ensure that the dir value of xfrm_userpolicy_id is XFRM_POLICY_MAX or
 less, which allowed local users to cause a denial of service
 (out-of-bounds access) or possibly have unspecified other impact via an
 XFRM_MSG_MIGRATE xfrm Netlink message (bnc#1050231).
- CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2) allowed
 reinstallation of the Group Temporal Key (GTK) during the group key
 handshake, allowing an attacker within radio range to replay frames from
 access points to clients (bnc#1063667).
- ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp-extra", rpm: "kernel-bigsmp-extra~3.0.101~0.47.106.11.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra", rpm: "kernel-default-extra~3.0.101~0.47.106.11.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-extra", rpm: "kernel-pae-extra~3.0.101~0.47.106.11.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-extra", rpm: "kernel-ppc64-extra~3.0.101~0.47.106.11.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-extra", rpm: "kernel-trace-extra~3.0.101~0.47.106.11.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-extra", rpm: "kernel-xen-extra~3.0.101~0.47.106.11.1", rls: "SLES11.0" ) )){
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp", rpm: "kernel-bigsmp~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp-base", rpm: "kernel-bigsmp-base~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp-devel", rpm: "kernel-bigsmp-devel~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace", rpm: "kernel-trace~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-base", rpm: "kernel-trace-base~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-devel", rpm: "kernel-trace-devel~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.0.101~0.47.106.11.1", rls: "SLES11.0SP3" ) )){
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

