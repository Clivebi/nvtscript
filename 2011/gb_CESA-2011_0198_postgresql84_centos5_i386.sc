if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.880562" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:0198" );
	script_cve_id( "CVE-2010-4015" );
	script_name( "CentOS Update for postgresql84 CESA-2011:0198 centos5 i386" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-April/017383.html" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/8.4/static/release.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql84'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "postgresql84 on CentOS 5" );
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

  These updated postgresql84 packages upgrade PostgreSQL to version 8.4.7.
  Refer to the linked PostgreSQL Release Notes for a full list of changes.

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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "postgresql84", rpm: "postgresql84~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-contrib", rpm: "postgresql84-contrib~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-devel", rpm: "postgresql84-devel~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-docs", rpm: "postgresql84-docs~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-libs", rpm: "postgresql84-libs~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-plperl", rpm: "postgresql84-plperl~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-plpython", rpm: "postgresql84-plpython~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-pltcl", rpm: "postgresql84-pltcl~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-python", rpm: "postgresql84-python~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-server", rpm: "postgresql84-server~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-tcl", rpm: "postgresql84-tcl~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql84-test", rpm: "postgresql84-test~8.4.7~1.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
