if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850182" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-13 17:01:55 +0530 (Thu, 13 Dec 2012)" );
	script_cve_id( "CVE-2012-2122" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:0860-1" );
	script_name( "openSUSE: Security Advisory for mysql (openSUSE-SU-2012:0860-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.4|openSUSE12\\.1)" );
	script_tag( name: "affected", value: "mysql on openSUSE 12.1, openSUSE 11.4" );
	script_tag( name: "insight", value: "Fixing CVE-2012-2122: authentication bypass due to
  incorrect type casting" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
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
report = "";
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient16", rpm: "libmysqlclusterclient16~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient16-debuginfo", rpm: "libmysqlclusterclient16-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient_r16", rpm: "libmysqlclusterclient_r16~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient_r16-debuginfo", rpm: "libmysqlclusterclient_r16-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster", rpm: "mysql-cluster~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-bench", rpm: "mysql-cluster-bench~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-bench-debuginfo", rpm: "mysql-cluster-bench-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-client", rpm: "mysql-cluster-client~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-client-debuginfo", rpm: "mysql-cluster-client-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debug", rpm: "mysql-cluster-debug~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debug-debuginfo", rpm: "mysql-cluster-debug-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debuginfo", rpm: "mysql-cluster-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debugsource", rpm: "mysql-cluster-debugsource~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-extra", rpm: "mysql-cluster-ndb-extra~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-extra-debuginfo", rpm: "mysql-cluster-ndb-extra-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-management", rpm: "mysql-cluster-ndb-management~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-management-debuginfo", rpm: "mysql-cluster-ndb-management-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-storage", rpm: "mysql-cluster-ndb-storage~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-storage-debuginfo", rpm: "mysql-cluster-ndb-storage-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-tools", rpm: "mysql-cluster-ndb-tools~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-tools-debuginfo", rpm: "mysql-cluster-ndb-tools-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-test", rpm: "mysql-cluster-test~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-test-debuginfo", rpm: "mysql-cluster-test-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-tools", rpm: "mysql-cluster-tools~7.1.22~55.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-tools-debuginfo", rpm: "mysql-cluster-tools-debuginfo~7.1.22~55.1", rls: "openSUSE11.4" ) )){
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
if(release == "openSUSE12.1"){
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient16", rpm: "libmysqlclusterclient16~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient16-debuginfo", rpm: "libmysqlclusterclient16-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient_r16", rpm: "libmysqlclusterclient_r16~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclusterclient_r16-debuginfo", rpm: "libmysqlclusterclient_r16-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster", rpm: "mysql-cluster~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-bench", rpm: "mysql-cluster-bench~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-bench-debuginfo", rpm: "mysql-cluster-bench-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-client", rpm: "mysql-cluster-client~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-client-debuginfo", rpm: "mysql-cluster-client-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debug", rpm: "mysql-cluster-debug~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debug-debuginfo", rpm: "mysql-cluster-debug-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debuginfo", rpm: "mysql-cluster-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-debugsource", rpm: "mysql-cluster-debugsource~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-extra", rpm: "mysql-cluster-ndb-extra~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-extra-debuginfo", rpm: "mysql-cluster-ndb-extra-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-management", rpm: "mysql-cluster-ndb-management~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-management-debuginfo", rpm: "mysql-cluster-ndb-management-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-storage", rpm: "mysql-cluster-ndb-storage~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-storage-debuginfo", rpm: "mysql-cluster-ndb-storage-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-tools", rpm: "mysql-cluster-ndb-tools~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-ndb-tools-debuginfo", rpm: "mysql-cluster-ndb-tools-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-test", rpm: "mysql-cluster-test~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-test-debuginfo", rpm: "mysql-cluster-test-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-tools", rpm: "mysql-cluster-tools~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-cluster-tools-debuginfo", rpm: "mysql-cluster-tools-debuginfo~7.1.22~2.7.1", rls: "openSUSE12.1" ) )){
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

