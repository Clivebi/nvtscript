if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.880471" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:0197" );
	script_cve_id( "CVE-2010-4015" );
	script_name( "CentOS Update for postgresql CESA-2011:0197 centos4 i386" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-February/017253.html" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/8.1/static/release.html" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/8.4/static/release.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "postgresql on CentOS 4" );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational database management system
  (DBMS).

  A stack-based buffer overflow flaw was found in the way PostgreSQL
  processed certain tokens from an SQL query when the intarray module was
  enabled on a particular database. An authenticated database user running a
  specially-crafted SQL query could use this flaw to cause a temporary denial
  of service (postgres daemon crash) or, potentially, execute arbitrary code
  with the privileges of the database server. (CVE-2010-4015)

  Red Hat would like to thank Geoff Keating of the Apple Product Security
  team for reporting this issue.

  For Red Hat Enterprise Linux 4, the updated postgresql packages contain a
  backported patch for this issue. There are no other changes.

  For Red Hat Enterprise Linux 5, the updated postgresql packages upgrade
  PostgreSQL to version 8.1.23, and contain a backported patch for this
  issue. Refer to the linked PostgreSQL Release Notes for a full list of changes.

  For Red Hat Enterprise Linux 6, the updated postgresql packages upgrade
  PostgreSQL to version 8.4.7, which includes a fix for this issue. Refer to
  the linked PostgreSQL Release Notes for a full list of changes.

  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct this issue. If the postgresql service is running, it will be
  automatically restarted after installing this update." );
	script_tag( name: "solution", value: "Please install the updated packages." );
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
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-jdbc", rpm: "postgresql-jdbc~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-libs", rpm: "postgresql-libs~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-pl", rpm: "postgresql-pl~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-python", rpm: "postgresql-python~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-tcl", rpm: "postgresql-tcl~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~7.4.30~1.el4_8.2", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

