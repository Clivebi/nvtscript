if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2143.1" );
	script_cve_id( "CVE-2021-3580" );
	script_tag( name: "creation_date", value: "2021-06-24 02:16:28 +0000 (Thu, 24 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-13 17:51:00 +0000 (Fri, 13 Aug 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2143-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3|SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2143-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212143-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libnettle' package(s) announced via the SUSE-SU-2021:2143-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libnettle fixes the following issues:

CVE-2021-3580: Fixed a remote denial of service in the RSA decryption
 via manipulated ciphertext (bsc#1187060)." );
	script_tag( name: "affected", value: "'libnettle' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0, SUSE MicroOS 5.0." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4", rpm: "libhogweed4~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit", rpm: "libhogweed4-32bit~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit-debuginfo", rpm: "libhogweed4-32bit-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-debuginfo", rpm: "libhogweed4-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-devel", rpm: "libnettle-devel~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6", rpm: "libnettle6~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit", rpm: "libnettle6-32bit~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit-debuginfo", rpm: "libnettle6-32bit-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-debuginfo", rpm: "libnettle6-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4", rpm: "libhogweed4~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit", rpm: "libhogweed4-32bit~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit-debuginfo", rpm: "libhogweed4-32bit-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-debuginfo", rpm: "libhogweed4-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-devel", rpm: "libnettle-devel~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6", rpm: "libnettle6~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit", rpm: "libnettle6-32bit~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit-debuginfo", rpm: "libnettle6-32bit-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-debuginfo", rpm: "libnettle6-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP3" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4", rpm: "libhogweed4~3.4.1~4.18.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-debuginfo", rpm: "libhogweed4-debuginfo~3.4.1~4.18.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~3.4.1~4.18.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-devel", rpm: "libnettle-devel~3.4.1~4.18.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6", rpm: "libnettle6~3.4.1~4.18.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-debuginfo", rpm: "libnettle6-debuginfo~3.4.1~4.18.1", rls: "SLES15.0" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4", rpm: "libhogweed4~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit", rpm: "libhogweed4-32bit~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit-debuginfo", rpm: "libhogweed4-32bit-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-debuginfo", rpm: "libhogweed4-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-devel", rpm: "libnettle-devel~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6", rpm: "libnettle6~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit", rpm: "libnettle6-32bit~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit-debuginfo", rpm: "libnettle6-32bit-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-debuginfo", rpm: "libnettle6-debuginfo~3.4.1~4.18.1", rls: "SLES15.0SP1" ) )){
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

