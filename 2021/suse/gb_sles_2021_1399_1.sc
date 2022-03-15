if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1399.1" );
	script_cve_id( "CVE-2021-20305" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-19 00:15:00 +0000 (Sat, 19 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1399-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1399-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211399-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libnettle' package(s) announced via the SUSE-SU-2021:1399-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libnettle fixes the following issues:

CVE-2021-20305: Fixed the multiply function which was being called with
 out-of-range scalars (bsc#1184401, bsc#1183835)." );
	script_tag( name: "affected", value: "'libnettle' package(s) on HPE Helion Openstack 8, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9." );
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
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2", rpm: "libhogweed2~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-32bit", rpm: "libhogweed2-32bit~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo", rpm: "libhogweed2-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo-32bit", rpm: "libhogweed2-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4", rpm: "libnettle4~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-32bit", rpm: "libnettle4-32bit~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo", rpm: "libnettle4-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo-32bit", rpm: "libnettle4-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2", rpm: "libhogweed2~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-32bit", rpm: "libhogweed2-32bit~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo", rpm: "libhogweed2-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo-32bit", rpm: "libhogweed2-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4", rpm: "libnettle4~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-32bit", rpm: "libnettle4-32bit~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo", rpm: "libnettle4-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo-32bit", rpm: "libnettle4-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2", rpm: "libhogweed2~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-32bit", rpm: "libhogweed2-32bit~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo", rpm: "libhogweed2-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo-32bit", rpm: "libhogweed2-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4", rpm: "libnettle4~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-32bit", rpm: "libnettle4-32bit~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo", rpm: "libnettle4-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo-32bit", rpm: "libnettle4-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2", rpm: "libhogweed2~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-32bit", rpm: "libhogweed2-32bit~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo", rpm: "libhogweed2-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed2-debuginfo-32bit", rpm: "libhogweed2-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4", rpm: "libnettle4~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-32bit", rpm: "libnettle4-32bit~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo", rpm: "libnettle4-debuginfo~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle4-debuginfo-32bit", rpm: "libnettle4-debuginfo-32bit~2.7.1~13.3.1", rls: "SLES12.0SP5" ) )){
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

