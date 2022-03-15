if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3923.1" );
	script_cve_id( "CVE-2018-1059" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-21 10:29:00 +0000 (Tue, 21 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3923-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3923-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183923-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dpdk' package(s) announced via the SUSE-SU-2018:3923-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dpdk to version 16.11.8 provides the following security fix:
CVE-2018-1059: restrict untrusted guest to misuse virtio to corrupt host
 application (ovs-dpdk) memory which could have lead all VM to lose
 connectivity (bsc#1089638)

and following non-security fixes:
Enable the broadcom chipset family Broadcom NetXtreme II BCM57810
 (bsc#1073363)

Fix a latency problem by using cond_resched rather than
 schedule_timeout_interruptible (bsc#1069601)

Fix a syntax error affecting csh environment configuration (bsc#1102310)

Fixes in net/bnxt:
 * Fix HW Tx checksum offload check
 * Fix incorrect IO address handling in Tx
 * Fix Rx ring count limitation
 * Check access denied for HWRM commands
 * Fix RETA size
 * Fix close operation

Fixes in eal/linux:
 * Fix an invalid syntax in interrupts
 * Fix return codes on thread naming failure

Fixes in kni:
 * Fix crash with null name
 * Fix build with gcc 8.1

Fixes in net/thunderx:
 * Fix build with gcc optimization on
 * Avoid sq door bell write on zero packet

net/bonding: Fix MAC address reset

vhost: Fix missing increment of log cache count" );
	script_tag( name: "affected", value: "'dpdk' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~16.11.8~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~16.11.8~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~16.11.8~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~16.11.8_k4.4.156_94.64~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~16.11.8_k4.4.156_94.64~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx", rpm: "dpdk-thunderx~16.11.8~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debuginfo", rpm: "dpdk-thunderx-debuginfo~16.11.8~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debugsource", rpm: "dpdk-thunderx-debugsource~16.11.8~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default", rpm: "dpdk-thunderx-kmp-default~16.11.8_k4.4.156_94.64~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default-debuginfo", rpm: "dpdk-thunderx-kmp-default-debuginfo~16.11.8_k4.4.156_94.64~8.10.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~16.11.8~8.10.2", rls: "SLES12.0SP3" ) )){
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

