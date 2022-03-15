if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850625" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2014-12-16 05:58:20 +0100 (Tue, 16 Dec 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "openSUSE: Security Advisory for Server (openSUSE-SU-2014:1642-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Server'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Firebird server crashes when handling a malformed network packet." );
	script_tag( name: "affected", value: "Server on openSUSE 13.1, openSUSE 12.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2014:1642-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE12\\.3|openSUSE13\\.1)" );
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
if(release == "openSUSE12.3"){
	if(!isnull( res = isrpmvuln( pkg: "firebird", rpm: "firebird~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic", rpm: "firebird-classic~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic-debuginfo", rpm: "firebird-classic-debuginfo~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic-debugsource", rpm: "firebird-classic-debugsource~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debuginfo", rpm: "firebird-debuginfo~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debugsource", rpm: "firebird-debugsource~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-devel", rpm: "firebird-devel~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver", rpm: "firebird-superserver~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver-debuginfo", rpm: "firebird-superserver-debuginfo~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2", rpm: "libfbclient2~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo", rpm: "libfbclient2-debuginfo~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-devel", rpm: "libfbclient2-devel~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed-devel", rpm: "libfbembed-devel~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2_5", rpm: "libfbembed2_5~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2_5-debuginfo", rpm: "libfbembed2_5-debuginfo~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-32bit", rpm: "firebird-32bit~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debuginfo-32bit", rpm: "firebird-debuginfo-32bit~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-32bit", rpm: "libfbclient2-32bit~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo-32bit", rpm: "libfbclient2-debuginfo-32bit~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-doc", rpm: "firebird-doc~2.5.2.26539~2.9.1", rls: "openSUSE12.3" ) )){
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "firebird", rpm: "firebird~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic", rpm: "firebird-classic~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic-debuginfo", rpm: "firebird-classic-debuginfo~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic-debugsource", rpm: "firebird-classic-debugsource~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debuginfo", rpm: "firebird-debuginfo~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debugsource", rpm: "firebird-debugsource~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-devel", rpm: "firebird-devel~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver", rpm: "firebird-superserver~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver-debuginfo", rpm: "firebird-superserver-debuginfo~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2", rpm: "libfbclient2~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo", rpm: "libfbclient2-debuginfo~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-devel", rpm: "libfbclient2-devel~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed-devel", rpm: "libfbembed-devel~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2_5", rpm: "libfbembed2_5~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2_5-debuginfo", rpm: "libfbembed2_5-debuginfo~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-32bit", rpm: "firebird-32bit~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debuginfo-32bit", rpm: "firebird-debuginfo-32bit~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-32bit", rpm: "libfbclient2-32bit~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo-32bit", rpm: "libfbclient2-debuginfo-32bit~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-doc", rpm: "firebird-doc~2.5.2.26539~8.4.1", rls: "openSUSE13.1" ) )){
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

