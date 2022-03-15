if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0932.1" );
	script_cve_id( "CVE-2016-1544", "CVE-2018-1000168", "CVE-2019-9511", "CVE-2019-9513", "CVE-2020-11080" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-05 13:58:00 +0000 (Tue, 05 Mar 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0932-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0932-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210932-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nghttp2' package(s) announced via the SUSE-SU-2021:0932-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nghttp2 fixes the following issues:

Security issues fixed:

CVE-2020-11080: HTTP/2 Large Settings Frame DoS (bsc#1181358).

CVE-2019-9513: Fixed HTTP/2 implementation that is vulnerable to
 resource loops, potentially leading to a denial of service (bsc#1146184).

CVE-2019-9511: Fixed HTTP/2 implementations that are vulnerable to
 window size manipulation and stream prioritization manipulation,
 potentially leading to a denial of service (bsc#1146182).

CVE-2018-1000168: Fixed ALTSVC frame client side denial of service
 (bsc#1088639).

CVE-2016-1544: Fixed out of memory due to unlimited incoming HTTP header
 fields (bsc#966514).

Bug fixes and enhancements:

Packages must not mark license files as %doc (bsc#1082318)

Typo in description of libnghttp2_asio1 (bsc#962914)

Fixed mistake in spec file (bsc#1125689)

Fixed build issue with boost 1.70.0 (bsc#1134616)

Fixed build issue with GCC 6 (bsc#964140)

Feature: Add W&S module (FATE#326776, bsc#1112438)" );
	script_tag( name: "affected", value: "'nghttp2' package(s) on HPE Helion Openstack 8, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9." );
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
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14", rpm: "libnghttp2-14~1.39.2~3.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-debuginfo", rpm: "libnghttp2-14-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debuginfo", rpm: "nghttp2-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debugsource", rpm: "nghttp2-debugsource~1.39.2~3.5.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14", rpm: "libnghttp2-14~1.39.2~3.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-debuginfo", rpm: "libnghttp2-14-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debuginfo", rpm: "nghttp2-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debugsource", rpm: "nghttp2-debugsource~1.39.2~3.5.1", rls: "SLES12.0SP3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14", rpm: "libnghttp2-14~1.39.2~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-32bit", rpm: "libnghttp2-14-32bit~1.39.2~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-debuginfo", rpm: "libnghttp2-14-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-debuginfo-32bit", rpm: "libnghttp2-14-debuginfo-32bit~1.39.2~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debuginfo", rpm: "nghttp2-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debugsource", rpm: "nghttp2-debugsource~1.39.2~3.5.1", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14", rpm: "libnghttp2-14~1.39.2~3.5.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-32bit", rpm: "libnghttp2-14-32bit~1.39.2~3.5.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-debuginfo", rpm: "libnghttp2-14-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-debuginfo-32bit", rpm: "libnghttp2-14-debuginfo-32bit~1.39.2~3.5.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debuginfo", rpm: "nghttp2-debuginfo~1.39.2~3.5.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debugsource", rpm: "nghttp2-debugsource~1.39.2~3.5.1", rls: "SLES12.0SP5" ) )){
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

