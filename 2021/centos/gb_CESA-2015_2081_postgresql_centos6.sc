if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882328" );
	script_version( "2021-04-21T15:24:38+0000" );
	script_cve_id( "CVE-2015-5288" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-21 15:24:38 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-21 14:10:46 +0000 (Wed, 21 Apr 2021)" );
	script_name( "CentOS: Security Advisory for postgresql (CESA-2015:2081)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "Advisory-ID", value: "CESA-2015:2081" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2015-November/021504.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql'
  package(s) announced via the CESA-2015:2081 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational
database management system (DBMS).

A memory leak error was discovered in the crypt() function of the pgCrypto
extension. An authenticated attacker could possibly use this flaw to
disclose a limited amount of the server memory. (CVE-2015-5288)

All PostgreSQL users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. If the postgresql
service is running, it will be automatically restarted after installing
this update." );
	script_tag( name: "affected", value: "'postgresql' package(s) on CentOS 6." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-libs", rpm: "postgresql-libs~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~8.4.20~4.el6_7", rls: "CentOS6" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

