if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-October/016180.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880858" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:1485" );
	script_cve_id( "CVE-2009-3230", "CVE-2007-6600" );
	script_name( "CentOS Update for rh-postgresql CESA-2009:1485 centos3 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rh-postgresql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS3" );
	script_tag( name: "affected", value: "rh-postgresql on CentOS 3" );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational database management system
  (DBMS).

  It was discovered that the upstream patch for CVE-2007-6600 included in the
  Red Hat Security Advisory RHSA-2008:0039 did not include protection against
  misuse of the RESET ROLE and RESET SESSION AUTHORIZATION commands. An
  authenticated user could use this flaw to install malicious code that would
  later execute with superuser privileges. (CVE-2009-3230)

  All PostgreSQL users should upgrade to these updated packages, which
  contain a backported patch to correct this issue. If you are running a
  PostgreSQL server, the postgresql service must be restarted for this update
  to take effect." );
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
if(release == "CentOS3"){
	if(( res = isrpmvuln( pkg: "rh-postgresql", rpm: "rh-postgresql~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-contrib", rpm: "rh-postgresql-contrib~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-devel", rpm: "rh-postgresql-devel~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-docs", rpm: "rh-postgresql-docs~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-jdbc", rpm: "rh-postgresql-jdbc~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-libs", rpm: "rh-postgresql-libs~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-pl", rpm: "rh-postgresql-pl~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-python", rpm: "rh-postgresql-python~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-server", rpm: "rh-postgresql-server~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-tcl", rpm: "rh-postgresql-tcl~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rh-postgresql-test", rpm: "rh-postgresql-test~7.3.21~2", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

