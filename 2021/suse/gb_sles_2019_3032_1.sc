if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3032.1" );
	script_cve_id( "CVE-2019-14818" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3032-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3032-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193032-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dpdk' package(s) announced via the SUSE-SU-2019:3032-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dpdk to version 17.11.7 fixes the following issues:
CVE-2019-14818: Fixed a memory leak vulnerability caused by a malicious
 container may lead to denial of service (bsc#1156146)." );
	script_tag( name: "affected", value: "'dpdk' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~17.11.7_k4.12.14_95.37~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~17.11.7_k4.12.14_95.37~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx", rpm: "dpdk-thunderx~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debuginfo", rpm: "dpdk-thunderx-debuginfo~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debugsource", rpm: "dpdk-thunderx-debugsource~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default", rpm: "dpdk-thunderx-kmp-default~17.11.7_k4.12.14_95.37~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default-debuginfo", rpm: "dpdk-thunderx-kmp-default-debuginfo~17.11.7_k4.12.14_95.37~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools-debuginfo", rpm: "dpdk-tools-debuginfo~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-17_11", rpm: "libdpdk-17_11~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-17_11-debuginfo", rpm: "libdpdk-17_11-debuginfo~17.11.7~5.3.2", rls: "SLES12.0SP4" ) )){
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

