if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882406" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:41 +0530 (Tue, 08 Mar 2016)" );
	script_cve_id( "CVE-2016-0773" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for postgresql CESA-2016:0347 centos6" );
	script_tag( name: "summary", value: "Check the version of postgresql" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational
database management system (DBMS).

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the PostgreSQL handling code for regular expressions. A remote
attacker could use a specially crafted regular expression to cause
PostgreSQL to crash or possibly execute arbitrary code. (CVE-2016-0773)

Red Hat would like to thank PostgreSQL upstream for reporting this issue.
Upstream acknowledges Tom Lane and Greg Stark as the original reporters.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. If the postgresql
service is running, it will be automatically restarted after installing
this update." );
	script_tag( name: "affected", value: "postgresql on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0347" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-March/021715.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-libs", rpm: "postgresql-libs~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~8.4.20~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

