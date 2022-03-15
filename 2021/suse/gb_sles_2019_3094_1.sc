if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3094.1" );
	script_cve_id( "CVE-2018-10754", "CVE-2019-17594", "CVE-2019-17595" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-08 20:52:00 +0000 (Mon, 08 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3094-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3094-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193094-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ncurses' package(s) announced via the SUSE-SU-2019:3094-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ncurses fixes the following issues:

Security issue fixed:
CVE-2018-10754: Fixed a denial of service caused by a NULL Pointer
 Dereference in the _nc_parse_entry() (bsc#1131830).

CVE-2019-17594: Fixed a heap-based buffer over-read in _nc_find_entry
 function in tinfo/comp_hash.c (bsc#1154036).

CVE-2019-17595: Fixed a heap-based buffer over-read in fmt_entry
 function in tinfo/comp_hash.c (bsc#1154037).

Bug fixes:
Fixed ppc64le build configuration (bsc#1134550)." );
	script_tag( name: "affected", value: "'ncurses' package(s) on SUSE CaaS Platform 3.0, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit", rpm: "libncurses5-32bit~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5", rpm: "libncurses5~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-debuginfo-32bit", rpm: "libncurses5-debuginfo-32bit~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-debuginfo", rpm: "libncurses5-debuginfo~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit", rpm: "libncurses6-32bit~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6", rpm: "libncurses6~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-debuginfo-32bit", rpm: "libncurses6-debuginfo-32bit~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-debuginfo", rpm: "libncurses6-debuginfo~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-debugsource", rpm: "ncurses-debugsource~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit", rpm: "ncurses-devel-32bit~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel", rpm: "ncurses-devel~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-debuginfo-32bit", rpm: "ncurses-devel-debuginfo-32bit~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-debuginfo", rpm: "ncurses-devel-debuginfo~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils", rpm: "ncurses-utils~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils-debuginfo", rpm: "ncurses-utils-debuginfo~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack", rpm: "tack~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack-debuginfo", rpm: "tack-debuginfo~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo", rpm: "terminfo~5.9~69.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-base", rpm: "terminfo-base~5.9~69.1", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-32bit", rpm: "libncurses5-32bit~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5", rpm: "libncurses5~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-debuginfo-32bit", rpm: "libncurses5-debuginfo-32bit~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses5-debuginfo", rpm: "libncurses5-debuginfo~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-32bit", rpm: "libncurses6-32bit~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6", rpm: "libncurses6~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-debuginfo-32bit", rpm: "libncurses6-debuginfo-32bit~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libncurses6-debuginfo", rpm: "libncurses6-debuginfo~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-debugsource", rpm: "ncurses-debugsource~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-32bit", rpm: "ncurses-devel-32bit~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel", rpm: "ncurses-devel~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-debuginfo-32bit", rpm: "ncurses-devel-debuginfo-32bit~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel-debuginfo", rpm: "ncurses-devel-debuginfo~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils", rpm: "ncurses-utils~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-utils-debuginfo", rpm: "ncurses-utils-debuginfo~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack", rpm: "tack~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tack-debuginfo", rpm: "tack-debuginfo~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo", rpm: "terminfo~5.9~69.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "terminfo-base", rpm: "terminfo-base~5.9~69.1", rls: "SLES12.0SP5" ) )){
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

