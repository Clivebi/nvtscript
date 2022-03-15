if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851139" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-12-11 05:48:10 +0100 (Fri, 11 Dec 2015)" );
	script_cve_id( "CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4807", "CVE-2015-4815", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4913" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for Security (openSUSE-SU-2015:2244-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Security'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MariaDB was updated to 10.0.22 to fix security issues and bugs.

  The following vulnerabilities were fixed in the upstream release:

  CVE-2015-4802, CVE-2015-4807, CVE-2015-4815, CVE-2015-4826,
  CVE-2015-4830, CVE-2015-4836, CVE-2015-4858, CVE-2015-4861, CVE-2015-4870,
  CVE-2015-4913, CVE-2015-4792

  A list of upstream changes and release notes can be found at the referenced notes.

  The following build problems were fixed:

  * bsc#937787: fix main.bootstrap test (change default charset to utf8 in
  test result)" );
	script_tag( name: "affected", value: "Security on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:2244-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
	script_xref( name: "URL", value: "https://kb.askmonty.org/en/mariadb-10022-release-notes/" );
	script_xref( name: "URL", value: "https://kb.askmonty.org/en/mariadb-10022-changelog/" );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient-devel", rpm: "libmysqlclient-devel~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18", rpm: "libmysqlclient18~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo", rpm: "libmysqlclient18-debuginfo~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient_r18", rpm: "libmysqlclient_r18~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld-devel", rpm: "libmysqld-devel~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld18", rpm: "libmysqld18~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld18-debuginfo", rpm: "libmysqld18-debuginfo~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench", rpm: "mariadb-bench~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench-debuginfo", rpm: "mariadb-bench-debuginfo~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client", rpm: "mariadb-client~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client-debuginfo", rpm: "mariadb-client-debuginfo~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debuginfo", rpm: "mariadb-debuginfo~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debugsource", rpm: "mariadb-debugsource~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-errormessages", rpm: "mariadb-errormessages~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test", rpm: "mariadb-test~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test-debuginfo", rpm: "mariadb-test-debuginfo~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools", rpm: "mariadb-tools~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools-debuginfo", rpm: "mariadb-tools-debuginfo~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-32bit", rpm: "libmysqlclient18-32bit~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo-32bit", rpm: "libmysqlclient18-debuginfo-32bit~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient_r18-32bit", rpm: "libmysqlclient_r18-32bit~10.0.22~2.18.1", rls: "openSUSE13.2" ) )){
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

