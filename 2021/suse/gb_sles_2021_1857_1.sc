if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1857.1" );
	script_cve_id( "CVE-2021-3500" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 11:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1857-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1857-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211857-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'djvulibre' package(s) announced via the SUSE-SU-2021:1857-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for djvulibre fixes the following issues:

CVE-2021-3500: Stack overflow in function
 DJVU:DjVuDocument:get_djvu_file() via crafted djvu file (bsc#1186253)" );
	script_tag( name: "affected", value: "'djvulibre' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "djvulibre-debuginfo", rpm: "djvulibre-debuginfo~3.5.27~3.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "djvulibre-debugsource", rpm: "djvulibre-debugsource~3.5.27~3.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre-devel", rpm: "libdjvulibre-devel~3.5.27~3.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre21", rpm: "libdjvulibre21~3.5.27~3.14.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre21-debuginfo", rpm: "libdjvulibre21-debuginfo~3.5.27~3.14.1", rls: "SLES15.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "djvulibre-debuginfo", rpm: "djvulibre-debuginfo~3.5.27~3.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "djvulibre-debugsource", rpm: "djvulibre-debugsource~3.5.27~3.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre-devel", rpm: "libdjvulibre-devel~3.5.27~3.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre21", rpm: "libdjvulibre21~3.5.27~3.14.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre21-debuginfo", rpm: "libdjvulibre21-debuginfo~3.5.27~3.14.1", rls: "SLES15.0SP1" ) )){
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

