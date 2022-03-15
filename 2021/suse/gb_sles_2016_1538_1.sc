if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.1538.1" );
	script_cve_id( "CVE-2015-8806", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449", "CVE-2016-4483" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:1538-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:1538-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20161538-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2016:1538-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libxml2 fixes the following security issues:
- CVE-2016-2073, CVE-2015-8806, CVE-2016-1839: A Heap-buffer overread was
 fixed in libxml2/dict.c [bsc#963963, bsc#965283, bsc#981114].
- CVE-2016-4483: Code was added to avoid an out of bound access when
 serializing malformed strings [bsc#978395].
- CVE-2016-1762: Fixed a heap-based buffer overread in xmlNextChar
 [bsc#981040].
- CVE-2016-1834: Fixed a heap-buffer-overflow in xmlStrncat [bsc#981041].
- CVE-2016-1833: Fixed a heap-based buffer overread in htmlCurrentChar
 [bsc#981108].
- CVE-2016-1835: Fixed a heap use-after-free in xmlSAX2AttributeNs
 [bsc#981109].
- CVE-2016-1837: Fixed a heap use-after-free in htmlParsePubidLiteral and
 htmlParseSystemiteral [bsc#981111].
- CVE-2016-1838: Fixed a heap-based buffer overread in
 xmlParserPrintFileContextInternal [bsc#981112].
- CVE-2016-1840: Fixed a heap-buffer-overflow in xmlFAParsePosCharGroup
 [bsc#981115].
- CVE-2016-4447: Fixed a heap-based buffer-underreads due to xmlParseName
 [bsc#981548].
- CVE-2016-4448: Fixed some format string warnings with possible format
 string vulnerability [bsc#981549],
- CVE-2016-4449: Fixed inappropriate fetch of entities content
 [bsc#981550].
- CVE-2016-3705: Fixed missing increment of recursion counter." );
	script_tag( name: "affected", value: "'libxml2' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2", rpm: "libxml2-2~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-32bit", rpm: "libxml2-2-32bit~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-debuginfo", rpm: "libxml2-2-debuginfo~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-debuginfo-32bit", rpm: "libxml2-2-debuginfo-32bit~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-debugsource", rpm: "libxml2-debugsource~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-doc", rpm: "libxml2-doc~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools", rpm: "libxml2-tools~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools-debuginfo", rpm: "libxml2-tools-debuginfo~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2", rpm: "python-libxml2~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2-debuginfo", rpm: "python-libxml2-debuginfo~2.9.1~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2-debugsource", rpm: "python-libxml2-debugsource~2.9.1~24.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2", rpm: "libxml2-2~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-32bit", rpm: "libxml2-2-32bit~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-debuginfo", rpm: "libxml2-2-debuginfo~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-debuginfo-32bit", rpm: "libxml2-2-debuginfo-32bit~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-debugsource", rpm: "libxml2-debugsource~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-doc", rpm: "libxml2-doc~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools", rpm: "libxml2-tools~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools-debuginfo", rpm: "libxml2-tools-debuginfo~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2", rpm: "python-libxml2~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2-debuginfo", rpm: "python-libxml2-debuginfo~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2-debugsource", rpm: "python-libxml2-debugsource~2.9.1~24.1", rls: "SLES12.0SP1" ) )){
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

