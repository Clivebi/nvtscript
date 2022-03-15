if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850176" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-13 17:01:30 +0530 (Thu, 13 Dec 2012)" );
	script_cve_id( "CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "openSUSE-SU", value: "2012:0489-1" );
	script_name( "openSUSE: Security Advisory for freetype2 (openSUSE-SU-2012:0489-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetype2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.4|openSUSE12\\.1)" );
	script_tag( name: "affected", value: "freetype2 on openSUSE 12.1, openSUSE 11.4" );
	script_tag( name: "insight", value: "Specially crafted font files could cause buffer overflows
  in freetype" );
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
	if(!isnull( res = isrpmvuln( pkg: "freetype2-debugsource", rpm: "freetype2-debugsource~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel", rpm: "freetype2-devel~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6", rpm: "libfreetype6~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-debuginfo", rpm: "libfreetype6-debuginfo~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel-32bit", rpm: "freetype2-devel-32bit~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-32bit", rpm: "libfreetype6-32bit~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-debuginfo-32bit", rpm: "libfreetype6-debuginfo-32bit~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-debuginfo-x86", rpm: "libfreetype6-debuginfo-x86~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-x86", rpm: "libfreetype6-x86~2.4.4~7.24.1", rls: "openSUSE11.4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "freetype2-debugsource", rpm: "freetype2-debugsource~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel", rpm: "freetype2-devel~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6", rpm: "libfreetype6~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-debuginfo", rpm: "libfreetype6-debuginfo~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel-32bit", rpm: "freetype2-devel-32bit~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-32bit", rpm: "libfreetype6-32bit~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-debuginfo-32bit", rpm: "libfreetype6-debuginfo-32bit~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-debuginfo-x86", rpm: "libfreetype6-debuginfo-x86~2.4.7~6.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-x86", rpm: "libfreetype6-x86~2.4.7~6.1", rls: "openSUSE12.1" ) )){
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

