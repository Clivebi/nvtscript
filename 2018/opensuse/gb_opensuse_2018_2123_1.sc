if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852044" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_cve_id( "CVE-2018-10805", "CVE-2018-11624", "CVE-2018-11625", "CVE-2018-12599", "CVE-2018-12600" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-06 13:28:00 +0000 (Wed, 06 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:37:21 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for ImageMagick (openSUSE-SU-2018:2123-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2123-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-07/msg00040.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the openSUSE-SU-2018:2123-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

  The following security vulnerabilities were fixed:

  - CVE-2018-11625: Fixed heap-based buffer over-read in SetGrayscaleImage
  in the quantize.c file, which allowed remote attackers to cause buffer
  over-read via a crafted file. (bsc#1096200)

  - CVE-2018-11624: Fixed a use-after-free issue in the ReadMATImage
  function in coders/mat.c. (bsc#1096203)

  - CVE-2018-10805: Fixed several memory leaks in bgr.c, rgb.c, cmyk.c,
  gray.c, and ycbcr.c (bsc#1095812)

  - CVE-2018-12600: The ReadDIBImage and WriteDIBImage functions allowed
  attackers to cause an out of bounds write via a crafted file
  (bsc#1098545).

  - CVE-2018-12599: The ReadBMPImage and WriteBMPImage functions allowed
  attackers to cause an out of bounds write via a crafted file
  (bsc#1098546).

  The following other changes were made:

  - Fix -gamma issues in special cases. (bsc#1094745, bsc#1094742)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-778=1" );
	script_tag( name: "affected", value: "ImageMagick on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel", rpm: "ImageMagick-devel~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra", rpm: "ImageMagick-extra~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra-debuginfo", rpm: "ImageMagick-extra-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4", rpm: "libMagick++-7_Q16HDRI4~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-debuginfo", rpm: "libMagick++-7_Q16HDRI4-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel", rpm: "libMagick++-devel~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6", rpm: "libMagickCore-7_Q16HDRI6~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6", rpm: "libMagickWand-7_Q16HDRI6~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick", rpm: "perl-PerlMagick~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick-debuginfo", rpm: "perl-PerlMagick-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-doc", rpm: "ImageMagick-doc~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel-32bit", rpm: "ImageMagick-devel-32bit~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit", rpm: "libMagick++-7_Q16HDRI4-32bit~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit-debuginfo", rpm: "libMagick++-7_Q16HDRI4-32bit-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel-32bit", rpm: "libMagick++-devel-32bit~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit", rpm: "libMagickCore-7_Q16HDRI6-32bit~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit", rpm: "libMagickWand-7_Q16HDRI6-32bit~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

