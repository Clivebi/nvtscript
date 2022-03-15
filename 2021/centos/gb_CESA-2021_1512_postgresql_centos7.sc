if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883356" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_cve_id( "CVE-2019-10208", "CVE-2020-25694", "CVE-2020-25695" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-07 02:15:00 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2021-06-15 03:01:07 +0000 (Tue, 15 Jun 2021)" );
	script_name( "CentOS: Security Advisory for postgresql (CESA-2021:1512)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:1512" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-June/048338.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql'
  package(s) announced via the CESA-2021:1512 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational database management system
(DBMS).

Security Fix(es):

  * postgresql: Reconnection can downgrade connection security settings
(CVE-2020-25694)

  * postgresql: Multiple features escape 'security restricted operation'
sandbox (CVE-2020-25695)

  * postgresql: TYPE in pg_temp executes arbitrary SQL during SECURITY
DEFINER execution (CVE-2019-10208)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'postgresql' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-libs", rpm: "postgresql-libs~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-static", rpm: "postgresql-static~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~9.2.24~6.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql-upgrade", rpm: "postgresql-upgrade~9.2.24~6.el7_9", rls: "CentOS7" ) )){
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

