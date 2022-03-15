if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850819" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)" );
	script_cve_id( "CVE-2014-2484", "CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4214", "CVE-2014-4233", "CVE-2014-4238", "CVE-2014-4240", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for MySQL (SUSE-SU-2014:1072-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MySQL'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This MySQL update provides the following:

  * upgrade to version 5.5.39, [bnc#887580]

  * CVE's fixed: CVE-2014-2484, CVE-2014-4258, CVE-2014-4260,
  CVE-2014-2494, CVE-2014-4238, CVE-2014-4207, CVE-2014-4233,
  CVE-2014-4240, CVE-2014-4214, CVE-2014-4243" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html" );
	script_tag( name: "affected", value: "MySQL on SUSE Linux Enterprise Server 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:1072-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP3" );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18", rpm: "libmysql55client18~5.5.39~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client_r18", rpm: "libmysql55client_r18~5.5.39~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient15", rpm: "libmysqlclient15~5.0.96~0.6.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient_r15", rpm: "libmysqlclient_r15~5.0.96~0.6.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.5.39~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-client", rpm: "mysql-client~5.5.39~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-tools", rpm: "mysql-tools~5.5.39~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18-32bit", rpm: "libmysql55client18-32bit~5.5.39~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient15-32bit", rpm: "libmysqlclient15-32bit~5.0.96~0.6.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql55client18-x86", rpm: "libmysql55client18-x86~5.5.39~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient15-x86", rpm: "libmysqlclient15-x86~5.0.96~0.6.13", rls: "SLES11.0SP3" ) )){
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

