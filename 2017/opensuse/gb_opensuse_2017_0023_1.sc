if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851467" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-05 05:43:02 +0100 (Thu, 05 Jan 2017)" );
	script_cve_id( "CVE-2014-9848", "CVE-2016-8707", "CVE-2016-8866", "CVE-2016-9556", "CVE-2016-9559", "CVE-2016-9773" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for ImageMagick (openSUSE-SU-2017:0023-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

  * CVE-2016-9556 Possible Heap-overflow found by fuzzing [bsc#1011130]

  * CVE-2016-9559 Possible Null pointer access found by fuzzing
  [bsc#1011136]

  * CVE-2016-8707 Possible code execution in Tiff convert utility
  [bsc#1014159]

  * CVE-2016-8866 Memory allocation failure in AcquireMagickMemory could
  lead to Heap overflow [bsc#1009318]

  * CVE-2016-9559 Possible Null pointer access found by fuzzing
  [bsc#1011136]

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "ImageMagick on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:0023-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel", rpm: "ImageMagick-devel~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra", rpm: "ImageMagick-extra~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra-debuginfo", rpm: "ImageMagick-extra-debuginfo~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-6_Q16-3", rpm: "libMagick++-6_Q16-3~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-6_Q16-3-debuginfo", rpm: "libMagick++-6_Q16-3-debuginfo~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel", rpm: "libMagick++-devel~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1", rpm: "libMagickCore-6_Q16-1~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1-debuginfo", rpm: "libMagickCore-6_Q16-1-debuginfo~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1", rpm: "libMagickWand-6_Q16-1~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1-debuginfo", rpm: "libMagickWand-6_Q16-1-debuginfo~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick", rpm: "perl-PerlMagick~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick-debuginfo", rpm: "perl-PerlMagick-debuginfo~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel-32bit", rpm: "ImageMagick-devel-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-6_Q16-3-32bit", rpm: "libMagick++-6_Q16-3-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-6_Q16-3-debuginfo-32bit", rpm: "libMagick++-6_Q16-3-debuginfo-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel-32bit", rpm: "libMagick++-devel-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1-32bit", rpm: "libMagickCore-6_Q16-1-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1-debuginfo-32bit", rpm: "libMagickCore-6_Q16-1-debuginfo-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1-32bit", rpm: "libMagickWand-6_Q16-1-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1-debuginfo-32bit", rpm: "libMagickWand-6_Q16-1-debuginfo-32bit~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-doc", rpm: "ImageMagick-doc~6.8.8.1~27.1", rls: "openSUSELeap42.1" ) )){
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

