if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882248" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-18 06:49:45 +0200 (Tue, 18 Aug 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for lemon CESA-2015:1635 centos7" );
	script_tag( name: "summary", value: "Check the version of lemon" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "SQLite is a C library that implements an SQL database engine. A large
subset of SQL92 is supported. A complete database is stored in a single
disk file. The API is designed for convenience and ease of use.
Applications that link against SQLite can enjoy the power and flexibility
of an SQL database without the administrative hassles of supporting a
separate database server.

A flaw was found in the way SQLite handled dequoting of collation-sequence
names. A local attacker could submit a specially crafted COLLATE statement
that would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3414)

It was found that SQLite's sqlite3VdbeExec() function did not properly
implement comparison operators. A local attacker could submit a specially
crafted CHECK statement that would crash the SQLite process, or have other
unspecified impacts. (CVE-2015-3415)

It was found that SQLite's sqlite3VXPrintf() function did not properly
handle precision and width values during floating-point conversions.
A local attacker could submit a specially crafted SELECT statement that
would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3416)

All sqlite users are advised to upgrade to this updated package, which
contains backported patches to correct these issues." );
	script_tag( name: "affected", value: "lemon on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1635" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-August/021337.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "lemon", rpm: "lemon~3.7.17~6.el7_1.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sqlite", rpm: "sqlite~3.7.17~6.el7_1.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sqlite-devel", rpm: "sqlite-devel~3.7.17~6.el7_1.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sqlite-doc", rpm: "sqlite-doc~3.7.17~6.el7_1.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sqlite-tcl", rpm: "sqlite-tcl~3.7.17~6.el7_1.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

