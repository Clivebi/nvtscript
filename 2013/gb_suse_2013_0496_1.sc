if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850453" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-11-19 14:05:36 +0530 (Tue, 19 Nov 2013)" );
	script_cve_id( "CVE-2013-2492" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2013:0496-1" );
	script_name( "openSUSE: Security Advisory for fix (openSUSE-SU-2013:0496-1)" );
	script_tag( name: "affected", value: "fix on openSUSE 12.2, openSUSE 12.1" );
	script_tag( name: "insight", value: "This update fixes a bug which allows an unauthenticated
  remote attacker to cause a stack overflow in server code,
  resulting in either server crash or even code execution as
  the user running firebird." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fix'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE12\\.2|openSUSE12\\.1)" );
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
if(release == "openSUSE12.2"){
	if(!isnull( res = isrpmvuln( pkg: "firebird", rpm: "firebird~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic", rpm: "firebird-classic~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic-debuginfo", rpm: "firebird-classic-debuginfo~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic-debugsource", rpm: "firebird-classic-debugsource~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debuginfo", rpm: "firebird-debuginfo~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debugsource", rpm: "firebird-debugsource~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-devel", rpm: "firebird-devel~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver", rpm: "firebird-superserver~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver-debuginfo", rpm: "firebird-superserver-debuginfo~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2", rpm: "libfbclient2~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo", rpm: "libfbclient2-debuginfo~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-devel", rpm: "libfbclient2-devel~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed-devel", rpm: "libfbembed-devel~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2_5", rpm: "libfbembed2_5~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2_5-debuginfo", rpm: "libfbembed2_5-debuginfo~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-32bit", rpm: "firebird-32bit~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debuginfo-32bit", rpm: "firebird-debuginfo-32bit~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-32bit", rpm: "libfbclient2-32bit~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo-32bit", rpm: "libfbclient2-debuginfo-32bit~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-doc", rpm: "firebird-doc~2.5.2.26539~2.8.1", rls: "openSUSE12.2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "firebird", rpm: "firebird~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic", rpm: "firebird-classic~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-classic-debuginfo", rpm: "firebird-classic-debuginfo~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debuginfo", rpm: "firebird-debuginfo~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-debugsource", rpm: "firebird-debugsource~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-devel", rpm: "firebird-devel~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-devel-debuginfo", rpm: "firebird-devel-debuginfo~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-doc", rpm: "firebird-doc~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-filesystem", rpm: "firebird-filesystem~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver", rpm: "firebird-superserver~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firebird-superserver-debuginfo", rpm: "firebird-superserver-debuginfo~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2", rpm: "libfbclient2~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo", rpm: "libfbclient2-debuginfo~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2", rpm: "libfbembed2~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2-debuginfo", rpm: "libfbembed2-debuginfo~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-32bit", rpm: "libfbclient2-32bit~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo-32bit", rpm: "libfbclient2-debuginfo-32bit~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2-32bit", rpm: "libfbembed2-32bit~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2-debuginfo-32bit", rpm: "libfbembed2-debuginfo-32bit~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-debuginfo-x86", rpm: "libfbclient2-debuginfo-x86~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbclient2-x86", rpm: "libfbclient2-x86~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2-debuginfo-x86", rpm: "libfbembed2-debuginfo-x86~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfbembed2-x86", rpm: "libfbembed2-x86~2.1.3.18185.0~22.4.1", rls: "openSUSE12.1" ) )){
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

