if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851663" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-13 07:44:03 +0100 (Wed, 13 Dec 2017)" );
	script_cve_id( "CVE-2017-10799", "CVE-2017-12140", "CVE-2017-12644", "CVE-2017-12662", "CVE-2017-14733", "CVE-2017-14994" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 00:15:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for GraphicsMagick (openSUSE-SU-2017:3270-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for GraphicsMagick fixes the following issues:

  * CVE-2017-12140: ReadDCMImage in coders\\dcm.c has a ninteger
  signedness error leading to excessive memory consumption
  (bnc#1051847)

  * CVE-2017-14994: NULL pointer in ReadDCMImage in coders/dcm.c could
  lead to denial of service (bnc#1061587)

  * CVE-2017-12662: Memory leak in WritePDFImage in coders/pdf.c could
  lead to denial of service (bnc#1052758)

  * CVE-2017-14733: Heap overflow on ReadRLEImage in coders/rle.c could
  lead to denial of service (bnc#1060577)

  * CVE-2017-12644: Memory leak in ReadDCMImage in coders\\dcm.c could
  lead to denial of service (bnc#1052764)

  * CVE-2017-10799: denial of service (OOM) can occur inReadDPXImage()
  (bnc#1047054)" );
	script_tag( name: "affected", value: "GraphicsMagick on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:3270-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debuginfo", rpm: "GraphicsMagick-debuginfo~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debugsource", rpm: "GraphicsMagick-debugsource~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-devel", rpm: "GraphicsMagick-devel~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12", rpm: "libGraphicsMagick++-Q16-12~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12-debuginfo", rpm: "libGraphicsMagick++-Q16-12-debuginfo~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-devel", rpm: "libGraphicsMagick++-devel~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3", rpm: "libGraphicsMagick-Q16-3~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3-debuginfo", rpm: "libGraphicsMagick-Q16-3-debuginfo~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick3-config", rpm: "libGraphicsMagick3-config~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2", rpm: "libGraphicsMagickWand-Q16-2~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2-debuginfo", rpm: "libGraphicsMagickWand-Q16-2-debuginfo~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick", rpm: "perl-GraphicsMagick~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick-debuginfo", rpm: "perl-GraphicsMagick-debuginfo~1.3.25~11.48.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debuginfo", rpm: "GraphicsMagick-debuginfo~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debugsource", rpm: "GraphicsMagick-debugsource~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-devel", rpm: "GraphicsMagick-devel~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12", rpm: "libGraphicsMagick++-Q16-12~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12-debuginfo", rpm: "libGraphicsMagick++-Q16-12-debuginfo~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-devel", rpm: "libGraphicsMagick++-devel~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3", rpm: "libGraphicsMagick-Q16-3~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3-debuginfo", rpm: "libGraphicsMagick-Q16-3-debuginfo~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick3-config", rpm: "libGraphicsMagick3-config~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2", rpm: "libGraphicsMagickWand-Q16-2~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2-debuginfo", rpm: "libGraphicsMagickWand-Q16-2-debuginfo~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick", rpm: "perl-GraphicsMagick~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick-debuginfo", rpm: "perl-GraphicsMagick-debuginfo~1.3.25~47.1", rls: "openSUSELeap42.3" ) )){
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

