if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850286" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 23:24:57 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2011-3256", "CVE-2011-3439" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "openSUSE-SU", value: "2012:0047-1" );
	script_name( "openSUSE: Security Advisory for freetype2 (openSUSE-SU-2012:0047-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetype2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.4|openSUSE11\\.3)" );
	script_tag( name: "affected", value: "freetype2 on openSUSE 11.4, openSUSE 11.3" );
	script_tag( name: "insight", value: "This update of freetype2 fixes multiple security flaws that
  could allow attackers to cause a denial of service or to
  execute arbitrary code via specially crafted fonts
  (CVE-2011-3256, CVE-2011-3439)." );
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
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel", rpm: "freetype2-devel~2.4.4~7.10.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6", rpm: "libfreetype6~2.4.4~7.10.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel-32bit", rpm: "freetype2-devel-32bit~2.4.4~7.10.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-32bit", rpm: "libfreetype6-32bit~2.4.4~7.10.1", rls: "openSUSE11.4" ) )){
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
if(release == "openSUSE11.3"){
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel", rpm: "freetype2-devel~2.3.12~7.8.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6", rpm: "libfreetype6~2.3.12~7.8.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel-32bit", rpm: "freetype2-devel-32bit~2.3.12~7.8.1", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreetype6-32bit", rpm: "libfreetype6-32bit~2.3.12~7.8.1", rls: "openSUSE11.3" ) )){
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

