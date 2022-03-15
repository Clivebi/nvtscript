if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851329" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-08 15:17:14 +0200 (Wed, 08 Jun 2016)" );
	script_cve_id( "CVE-2015-1283", "CVE-2016-0718" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-25 15:44:00 +0000 (Mon, 25 Jan 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for expat (openSUSE-SU-2016:1523-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'expat'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for expat fixes the following issues:

  Security issue fixed:

  - CVE-2016-0718: Fix Expat XML parser that mishandles certain kinds of
  malformed input documents. (bsc#979441)

  - CVE-2015-1283: Fix multiple integer overflows. (bnc#980391) This update
  was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "expat on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1523-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "expat", rpm: "expat~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo", rpm: "expat-debuginfo~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debugsource", rpm: "expat-debugsource~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat-devel", rpm: "libexpat-devel~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1", rpm: "libexpat1~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo", rpm: "libexpat1-debuginfo~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo-32bit", rpm: "expat-debuginfo-32bit~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat-devel-32bit", rpm: "libexpat-devel-32bit~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-32bit", rpm: "libexpat1-32bit~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo-32bit", rpm: "libexpat1-debuginfo-32bit~2.1.0~17.1", rls: "openSUSELeap42.1" ) )){
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

