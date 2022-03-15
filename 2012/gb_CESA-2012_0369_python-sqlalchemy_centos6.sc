if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-March/018474.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881193" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:40:02 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-0805" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:0369" );
	script_name( "CentOS Update for python-sqlalchemy CESA-2012:0369 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-sqlalchemy'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "python-sqlalchemy on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "SQLAlchemy is an Object Relational Mapper (ORM) that provides a flexible,
  high-level interface to SQL databases.

  It was discovered that SQLAlchemy did not sanitize values for the limit and
  offset keywords for SQL select statements. If an application using
  SQLAlchemy accepted values for these keywords, and did not filter or
  sanitize them before passing them to SQLAlchemy, it could allow an attacker
  to perform an SQL injection attack against the application. (CVE-2012-0805)

  All users of python-sqlalchemy are advised to upgrade to this updated
  package, which contains a patch to correct this issue. All running
  applications using SQLAlchemy must be restarted for this update to take
  effect." );
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
	if(( res = isrpmvuln( pkg: "python-sqlalchemy", rpm: "python-sqlalchemy~0.5.5~3.el6_2", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

