if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2971.1" );
	script_cve_id( "CVE-2019-2201" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-19 01:15:00 +0000 (Tue, 19 Nov 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2971-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2971-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192971-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libjpeg-turbo' package(s) announced via the SUSE-SU-2019:2971-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libjpeg-turbo fixes the following issues:
CVE-2019-2201: Several integer overflow issues and subsequent segfaults
 occurred in libjpeg-turbo, when attempting to compress or decompress
 gigapixel images. [bsc#1156402]" );
	script_tag( name: "affected", value: "'libjpeg-turbo' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "libjpeg62", rpm: "libjpeg62~62.2.0~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg62-debuginfo", rpm: "libjpeg62-debuginfo~62.2.0~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg62-devel", rpm: "libjpeg62-devel~62.2.0~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8", rpm: "libjpeg8~8.1.2~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-debuginfo", rpm: "libjpeg8-debuginfo~8.1.2~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-devel", rpm: "libjpeg8-devel~8.1.2~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libturbojpeg0", rpm: "libturbojpeg0~8.1.2~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libturbojpeg0-debuginfo", rpm: "libturbojpeg0-debuginfo~8.1.2~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-32bit", rpm: "libjpeg8-32bit~8.1.2~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-32bit-debuginfo", rpm: "libjpeg8-32bit-debuginfo~8.1.2~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg-turbo", rpm: "libjpeg-turbo~1.5.3~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg-turbo-debuginfo", rpm: "libjpeg-turbo-debuginfo~1.5.3~5.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg-turbo-debugsource", rpm: "libjpeg-turbo-debugsource~1.5.3~5.12.1", rls: "SLES15.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libjpeg62", rpm: "libjpeg62~62.2.0~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg62-debuginfo", rpm: "libjpeg62-debuginfo~62.2.0~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg62-devel", rpm: "libjpeg62-devel~62.2.0~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8", rpm: "libjpeg8~8.1.2~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-debuginfo", rpm: "libjpeg8-debuginfo~8.1.2~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-devel", rpm: "libjpeg8-devel~8.1.2~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libturbojpeg0", rpm: "libturbojpeg0~8.1.2~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libturbojpeg0-debuginfo", rpm: "libturbojpeg0-debuginfo~8.1.2~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-32bit", rpm: "libjpeg8-32bit~8.1.2~5.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjpeg8-32bit-debuginfo", rpm: "libjpeg8-32bit-debuginfo~8.1.2~5.12.1", rls: "SLES15.0SP1" ) )){
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

