if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871124" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-02-13 11:42:32 +0530 (Thu, 13 Feb 2014)" );
	script_cve_id( "CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0437" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "RedHat Update for mysql RHSA-2014:0164-01" );
	script_tag( name: "affected", value: "mysql on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "MySQL is a multi-user, multi-threaded SQL database server. It consists of
the MySQL server daemon (mysqld) and many client programs and libraries.

This update fixes several vulnerabilities in the MySQL database server.
Information about these flaws can be found on the Oracle Critical Patch
Update Advisory page, listed in the References section. (CVE-2014-0386,
CVE-2014-0393, CVE-2014-0401, CVE-2014-0402, CVE-2014-0412, CVE-2014-0437,
CVE-2013-5908)

A buffer overflow flaw was found in the way the MySQL command line client
tool (mysql) processed excessively long version strings. If a user
connected to a malicious MySQL server via the mysql client, the server
could use this flaw to crash the mysql client or, potentially, execute
arbitrary code as the user running the mysql client. (CVE-2014-0001)

The CVE-2014-0001 issue was discovered by Garth Mollett of the Red Hat
Security Response Team.

This update also fixes the following bug:

  * Prior to this update, MySQL did not check whether a MySQL socket was
actually being used by any process before starting the mysqld service. If a
particular mysqld service did not exit cleanly while a socket was being
used by a process, this socket was considered to be still in use during the
next start-up of this service, which resulted in a failure to start the
service up. With this update, if a socket exists but is not used by any
process, it is ignored during the mysqld service start-up. (BZ#1058719)

These updated packages upgrade MySQL to version 5.1.73. Refer to the MySQL
Release Notes listed in the References section for a complete list of
changes.

All MySQL users should upgrade to these updated packages, which correct
these issues. After installing this update, the MySQL server daemon
(mysqld) will be restarted automatically." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:0164-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-February/msg00017.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.1.73~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-bench", rpm: "mysql-bench~5.1.73~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-debuginfo", rpm: "mysql-debuginfo~5.1.73~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-devel", rpm: "mysql-devel~5.1.73~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-libs", rpm: "mysql-libs~5.1.73~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-server", rpm: "mysql-server~5.1.73~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-test", rpm: "mysql-test~5.1.73~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

