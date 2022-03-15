if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853028" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2019-19948", "CVE-2019-19949" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 20:15:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-02-06 04:01:04 +0000 (Thu, 06 Feb 2020)" );
	script_name( "openSUSE: Security Advisory for ImageMagick (openSUSE-SU-2020:0170-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0170-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00006.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the openSUSE-SU-2020:0170-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

  Security issue fixed:

  - CVE-2019-19948: Fixed a heap-based buffer overflow in WriteSGIImage()
  (bsc#1159861).

  - CVE-2019-19949: Fixed a heap-based buffer over-read in WritePNGImage()
  (bsc#1160369).

  Non-security issue fixed:

  - Fixed an issue where converting tiff to png would lead to unviewable
  files (bsc#1161194).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-170=1" );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-7-SUSE", rpm: "ImageMagick-config-7-SUSE~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-7-upstream", rpm: "ImageMagick-config-7-upstream~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel", rpm: "ImageMagick-devel~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra", rpm: "ImageMagick-extra~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra-debuginfo", rpm: "ImageMagick-extra-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4", rpm: "libMagick++-7_Q16HDRI4~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-debuginfo", rpm: "libMagick++-7_Q16HDRI4-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel", rpm: "libMagick++-devel~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6", rpm: "libMagickCore-7_Q16HDRI6~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6", rpm: "libMagickWand-7_Q16HDRI6~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick", rpm: "perl-PerlMagick~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick-debuginfo", rpm: "perl-PerlMagick-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel-32bit", rpm: "ImageMagick-devel-32bit~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit", rpm: "libMagick++-7_Q16HDRI4-32bit~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit-debuginfo", rpm: "libMagick++-7_Q16HDRI4-32bit-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel-32bit", rpm: "libMagick++-devel-32bit~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit", rpm: "libMagickCore-7_Q16HDRI6-32bit~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit", rpm: "libMagickWand-7_Q16HDRI6-32bit~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-doc", rpm: "ImageMagick-doc~7.0.7.34~lp151.7.15.1", rls: "openSUSELeap15.1" ) )){
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

