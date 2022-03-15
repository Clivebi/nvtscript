if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851322" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 16:25:14 +0530 (Fri, 03 Jun 2016)" );
	script_cve_id( "CVE-2015-1283", "CVE-2016-0718" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-25 15:44:00 +0000 (Mon, 25 Jan 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for expat (openSUSE-SU-2016:1441-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'expat'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for expat fixes the following security issues:

  - CVE-2015-1283: Fixed multiple integer overflows that could lead to
  buffer overflows [boo#980391]

  - CVE-2016-0718: Fixed Expat XML parser that mishandles certain kinds of
  malformed input documents [boo#979441]." );
	script_tag( name: "affected", value: "expat on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1441-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "expat", rpm: "expat~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo", rpm: "expat-debuginfo~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debugsource", rpm: "expat-debugsource~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat-devel", rpm: "libexpat-devel~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1", rpm: "libexpat1~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo", rpm: "libexpat1-debuginfo~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo-32bit", rpm: "expat-debuginfo-32bit~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat-devel-32bit", rpm: "libexpat-devel-32bit~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-32bit", rpm: "libexpat1-32bit~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo-32bit", rpm: "libexpat1-debuginfo-32bit~2.1.0~14.3.1", rls: "openSUSE13.2" ) )){
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

