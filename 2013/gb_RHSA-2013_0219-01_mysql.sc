if(description){
	script_tag( name: "affected", value: "mysql on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  This update fixes several vulnerabilities in the MySQL database server.
  Information about these flaws can be found on the Oracle Critical Patch
  Update Advisory page, listed in the References section. (CVE-2012-0572,
  CVE-2012-0574, CVE-2012-1702, CVE-2012-1705, CVE-2013-0375, CVE-2013-0383,
  CVE-2013-0384, CVE-2013-0385, CVE-2013-0389)

  These updated packages upgrade MySQL to version 5.1.67. Refer to the MySQL
  release notes listed in the References section for a full list of changes.

  All MySQL users should upgrade to these updated packages, which correct
  these issues. After installing this update, the MySQL server daemon
  (mysqld) will be restarted automatically." );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-January/msg00066.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870899" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-02-04 09:53:59 +0530 (Mon, 04 Feb 2013)" );
	script_cve_id( "CVE-2012-0572", "CVE-2012-0574", "CVE-2012-1702", "CVE-2012-1705", "CVE-2013-0375", "CVE-2013-0383", "CVE-2013-0384", "CVE-2013-0385", "CVE-2013-0389" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2013:0219-01" );
	script_name( "RedHat Update for mysql RHSA-2013:0219-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.1.67~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-bench", rpm: "mysql-bench~5.1.67~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-debuginfo", rpm: "mysql-debuginfo~5.1.67~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-devel", rpm: "mysql-devel~5.1.67~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-libs", rpm: "mysql-libs~5.1.67~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-server", rpm: "mysql-server~5.1.67~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-test", rpm: "mysql-test~5.1.67~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

