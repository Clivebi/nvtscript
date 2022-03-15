if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1492.1" );
	script_cve_id( "CVE-2018-1059" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-21 10:29:00 +0000 (Tue, 21 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1492-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1492-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181492-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dpdk-thunderxdpdk' package(s) announced via the SUSE-SU-2018:1492-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following issues:
 - CVE-2018-1059: The DPDK vhost-user interface does not check to verify
 that all the requested guest physical range is mapped and contiguous
 when performing Guest Physical Addresses to Host Virtual Addresses
 translations. This may lead to a malicious guest exposing vhost-user
 backend process memory. All versions before 18.02.1 are vulnerable.
 (bsc#1089638)." );
	script_tag( name: "affected", value: "'dpdk-thunderxdpdk' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~16.11.6~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~16.11.6~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~16.11.6~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~16.11.6_k4.4.126_94.22~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~16.11.6_k4.4.126_94.22~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx", rpm: "dpdk-thunderx~16.11.6~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debuginfo", rpm: "dpdk-thunderx-debuginfo~16.11.6~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debugsource", rpm: "dpdk-thunderx-debugsource~16.11.6~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default", rpm: "dpdk-thunderx-kmp-default~16.11.6_k4.4.126_94.22~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default-debuginfo", rpm: "dpdk-thunderx-kmp-default-debuginfo~16.11.6_k4.4.126_94.22~8.4.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~16.11.6~8.4.2", rls: "SLES12.0SP3" ) )){
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

