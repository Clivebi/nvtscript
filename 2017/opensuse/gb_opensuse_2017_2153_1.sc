if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851591" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-12 07:31:06 +0200 (Sat, 12 Aug 2017)" );
	script_cve_id( "CVE-2017-2885" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-07 17:15:00 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for libsoup (openSUSE-SU-2017:2153-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsoup'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libsoup fixes the following issues:

  - A bug in the HTTP Chunked Encoding code has been fixed that could have
  been exploited by attackers to cause a stack-based buffer overflow in
  client or server code running libsoup (bsc#1052916, CVE-2017-2885).

  This update was imported from the SUSE:SLE-12-SP2:Update update project." );
	script_tag( name: "affected", value: "libsoup on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2153-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1", rpm: "libsoup-2_4-1~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1-debuginfo", rpm: "libsoup-2_4-1-debuginfo~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-debugsource", rpm: "libsoup-debugsource~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-devel", rpm: "libsoup-devel~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Soup-2_4", rpm: "typelib-1_0-Soup-2_4~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1-32bit", rpm: "libsoup-2_4-1-32bit~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1-debuginfo-32bit", rpm: "libsoup-2_4-1-debuginfo-32bit~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-devel-32bit", rpm: "libsoup-devel-32bit~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-lang", rpm: "libsoup-lang~2.54.1~2.3.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1", rpm: "libsoup-2_4-1~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1-debuginfo", rpm: "libsoup-2_4-1-debuginfo~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-debugsource", rpm: "libsoup-debugsource~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-devel", rpm: "libsoup-devel~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Soup-2_4", rpm: "typelib-1_0-Soup-2_4~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-lang", rpm: "libsoup-lang~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1-32bit", rpm: "libsoup-2_4-1-32bit~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-2_4-1-debuginfo-32bit", rpm: "libsoup-2_4-1-debuginfo-32bit~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsoup-devel-32bit", rpm: "libsoup-devel-32bit~2.54.1~5.1", rls: "openSUSELeap42.3" ) )){
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

