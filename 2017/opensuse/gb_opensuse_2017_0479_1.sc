if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851491" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-17 05:51:55 +0100 (Fri, 17 Feb 2017)" );
	script_cve_id( "CVE-2016-8318", "CVE-2016-8327", "CVE-2017-3238", "CVE-2017-3244", "CVE-2017-3257", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3273", "CVE-2017-3291", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for mysql-community-server (openSUSE-SU-2017:0479-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-community-server'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "mysql-community-server was updated to version 5.6.35 to fix bugs and
  security issues:

  * Changes are available in the linked references.

  * Fixed CVEs: CVE-2016-8318 [boo#1020872], CVE-2017-3312 [boo#1020873],
  CVE-2017-3258 [boo#1020875], CVE-2017-3273 [boo#1020876], CVE-2017-3244
  [boo#1020877], CVE-2017-3257 [boo#1020878], CVE-2017-3238 [boo#1020882],
  CVE-2017-3291 [boo#1020884], CVE-2017-3265 [boo#1020885], CVE-2017-3313
  [boo#1020890], CVE-2016-8327 [boo#1020893], CVE-2017-3317 [boo#1020894],
  CVE-2017-3318 [boo#1020896]" );
	script_tag( name: "affected", value: "mysql-community-server on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:0479-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-35.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18", rpm: "libmysql56client18~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-debuginfo", rpm: "libmysql56client18-debuginfo~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client_r18", rpm: "libmysql56client_r18~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server", rpm: "mysql-community-server~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-bench", rpm: "mysql-community-server-bench~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-bench-debuginfo", rpm: "mysql-community-server-bench-debuginfo~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-client", rpm: "mysql-community-server-client~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-client-debuginfo", rpm: "mysql-community-server-client-debuginfo~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-debuginfo", rpm: "mysql-community-server-debuginfo~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-debugsource", rpm: "mysql-community-server-debugsource~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-errormessages", rpm: "mysql-community-server-errormessages~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-test", rpm: "mysql-community-server-test~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-test-debuginfo", rpm: "mysql-community-server-test-debuginfo~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-tools", rpm: "mysql-community-server-tools~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-tools-debuginfo", rpm: "mysql-community-server-tools-debuginfo~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-32bit", rpm: "libmysql56client18-32bit~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-debuginfo-32bit", rpm: "libmysql56client18-debuginfo-32bit~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client_r18-32bit", rpm: "libmysql56client_r18-32bit~5.6.35~22.1", rls: "openSUSELeap42.1" ) )){
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

