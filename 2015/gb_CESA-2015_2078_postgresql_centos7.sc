if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882329" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-20 06:27:39 +0100 (Fri, 20 Nov 2015)" );
	script_cve_id( "CVE-2015-5288", "CVE-2015-5289" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for postgresql CESA-2015:2078 centos7" );
	script_tag( name: "summary", value: "Check the version of postgresql" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational
database management system (DBMS).

A memory leak error was discovered in the crypt() function of the pgCrypto
extension. An authenticated attacker could possibly use this flaw to
disclose a limited amount of the server memory. (CVE-2015-5288)

A stack overflow flaw was discovered in the way the PostgreSQL core server
processed certain JSON or JSONB input. An authenticated attacker could
possibly use this flaw to crash the server backend by sending specially
crafted JSON or JSONB input. (CVE-2015-5289)

Please note that SSL renegotiation is now disabled by default. For more
information, please refer to PostgreSQL's 2015-10-08 Security Update
Release notes, linked to in the References section.

All PostgreSQL users are advised to upgrade to these updated packages,
which correct these issues. If the postgresql service is running, it will
be automatically restarted after installing this update." );
	script_tag( name: "affected", value: "postgresql on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:2078" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-November/021508.html" );
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
	if(( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-libs", rpm: "postgresql-libs~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-upgrade", rpm: "postgresql-upgrade~9.2.14~1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

