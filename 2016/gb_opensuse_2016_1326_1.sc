if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851317" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-19 05:22:09 +0200 (Thu, 19 May 2016)" );
	script_cve_id( "CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3717", "CVE-2016-3718" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 13:29:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for GraphicsMagick (openSUSE-SU-2016:1326-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for GraphicsMagick fixes the following issues:

  Security issues fixed:

  - Multiple security issues in GraphicsMagick/ImageMagick [boo#978061]
  (CVE-2016-3714, CVE-2016-3718, CVE-2016-3715, CVE-2016-3717)" );
	script_tag( name: "affected", value: "GraphicsMagick on openSUSE Leap 42.1, openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1326-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debuginfo", rpm: "GraphicsMagick-debuginfo~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debugsource", rpm: "GraphicsMagick-debugsource~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-devel", rpm: "GraphicsMagick-devel~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-3", rpm: "libGraphicsMagick++-Q16-3~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-3-debuginfo", rpm: "libGraphicsMagick++-Q16-3-debuginfo~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-devel", rpm: "libGraphicsMagick++-devel~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3", rpm: "libGraphicsMagick-Q16-3~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3-debuginfo", rpm: "libGraphicsMagick-Q16-3-debuginfo~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick3-config", rpm: "libGraphicsMagick3-config~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2", rpm: "libGraphicsMagickWand-Q16-2~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2-debuginfo", rpm: "libGraphicsMagickWand-Q16-2-debuginfo~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick", rpm: "perl-GraphicsMagick~1.3.20~3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick-debuginfo", rpm: "perl-GraphicsMagick-debuginfo~1.3.20~3.1", rls: "openSUSE13.2" ) )){
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

