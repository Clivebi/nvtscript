if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881725" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-02 11:05:13 +0530 (Thu, 02 May 2013)" );
	script_cve_id( "CVE-2012-5614", "CVE-2013-1506", "CVE-2013-1521", "CVE-2013-1531", "CVE-2013-1532", "CVE-2013-1544", "CVE-2013-1548", "CVE-2013-1552", "CVE-2013-1555", "CVE-2013-2375", "CVE-2013-2378", "CVE-2013-2389", "CVE-2013-2391", "CVE-2013-2392" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "CentOS Update for mysql CESA-2013:0772 centos6" );
	script_xref( name: "CESA", value: "2013:0772" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-April/019707.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "mysql on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  This update fixes several vulnerabilities in the MySQL database server.
  Information about these flaws can be found on the Oracle Critical Patch
  Update Advisory page, listed in the References section. (CVE-2012-5614,
  CVE-2013-1506, CVE-2013-1521, CVE-2013-1531, CVE-2013-1532, CVE-2013-1544,
  CVE-2013-1548, CVE-2013-1552, CVE-2013-1555, CVE-2013-2375, CVE-2013-2378,
  CVE-2013-2389, CVE-2013-2391, CVE-2013-2392)

  These updated packages upgrade MySQL to version 5.1.69. Refer to the MySQL
  release notes listed in the References section for a full list of changes.

  All MySQL users should upgrade to these updated packages, which correct
  these issues. After installing this update, the MySQL server daemon
  (mysqld) will be restarted automatically." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-bench", rpm: "mysql-bench~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-devel", rpm: "mysql-devel~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-embedded", rpm: "mysql-embedded~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-embedded-devel", rpm: "mysql-embedded-devel~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-libs", rpm: "mysql-libs~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-server", rpm: "mysql-server~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-test", rpm: "mysql-test~5.1.69~1.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

