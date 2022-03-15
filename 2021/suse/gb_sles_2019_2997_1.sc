if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2997.1" );
	script_cve_id( "CVE-2019-17594", "CVE-2019-17595" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-08 20:52:00 +0000 (Mon, 08 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2997-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2997-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192997-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ncurses' package(s) announced via the SUSE-SU-2019:2997-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ncurses fixes the following issues:

Security issues fixed:
CVE-2019-17594: Fixed a heap-based buffer over-read in the
 _nc_find_entry function (bsc#1154036).

CVE-2019-17595: Fixed a heap-based buffer over-read in the fmt_entry
 function (bsc#1154037).

Non-security issue fixed:
Removed screen.xterm from terminfo database (bsc#1103320)." );
	script_tag( name: "affected", value: "'ncurses' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit", rpm: "libncurses6-32bit~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit-debuginfo", rpm: "libncurses6-32bit-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6", rpm: "libncurses6~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-debuginfo", rpm: "libncurses6-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-debugsource", rpm: "ncurses-debugsource~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel", rpm: "ncurses-devel~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-debuginfo", rpm: "ncurses-devel-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils", rpm: "ncurses-utils~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils-debuginfo", rpm: "ncurses-utils-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack", rpm: "tack~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack-debuginfo", rpm: "tack-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo", rpm: "terminfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-base", rpm: "terminfo-base~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-iterm", rpm: "terminfo-iterm~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-screen", rpm: "terminfo-screen~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit", rpm: "ncurses-devel-32bit~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit-debuginfo", rpm: "ncurses-devel-32bit-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit", rpm: "libncurses5-32bit~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit-debuginfo", rpm: "libncurses5-32bit-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5", rpm: "libncurses5~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-debuginfo", rpm: "libncurses5-debuginfo~6.1~5.6.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses5-devel", rpm: "ncurses5-devel~6.1~5.6.2", rls: "SLES15.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit", rpm: "libncurses6-32bit~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit-debuginfo", rpm: "libncurses6-32bit-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6", rpm: "libncurses6~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-debuginfo", rpm: "libncurses6-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-debugsource", rpm: "ncurses-debugsource~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel", rpm: "ncurses-devel~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-debuginfo", rpm: "ncurses-devel-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils", rpm: "ncurses-utils~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils-debuginfo", rpm: "ncurses-utils-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack", rpm: "tack~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack-debuginfo", rpm: "tack-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo", rpm: "terminfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-base", rpm: "terminfo-base~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-iterm", rpm: "terminfo-iterm~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-screen", rpm: "terminfo-screen~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit", rpm: "ncurses-devel-32bit~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit-debuginfo", rpm: "ncurses-devel-32bit-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit", rpm: "libncurses5-32bit~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit-debuginfo", rpm: "libncurses5-32bit-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5", rpm: "libncurses5~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-debuginfo", rpm: "libncurses5-debuginfo~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses5-devel", rpm: "ncurses5-devel~6.1~5.6.2", rls: "SLES15.0SP1" ) )){
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

