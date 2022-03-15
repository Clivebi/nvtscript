if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851974" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-16323", "CVE-2018-16328", "CVE-2018-16329", "CVE-2018-16413", "CVE-2018-16640", "CVE-2018-16641", "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-25 16:23:00 +0000 (Thu, 25 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:24:24 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for ImageMagick (openSUSE-SU-2018:3014-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:3014-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00008.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the openSUSE-SU-2018:3014-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following security issues:

  - CVE-2018-16413: Prevent heap-based buffer over-read in the
  PushShortPixel function leading to DoS (bsc#1106989)

  - CVE-2018-16329: Prevent NULL pointer dereference in the
  GetMagickProperty function leading to DoS (bsc#1106858).

  - CVE-2018-16328: Prevent NULL pointer dereference exists in the
  CheckEventLogging function leading to DoS (bsc#1106857).

  - CVE-2018-16323: ReadXBMImage left data uninitialized when processing an
  XBM file that has a negative pixel value. If the affected code was used
  as a library loaded into a process that includes sensitive information,
  that information sometimes can be leaked via the image data (bsc#1106855)

  - CVE-2018-16642: The function InsertRow allowed remote attackers to cause
  a denial of service via a crafted image file due to an out-of-bounds
  write (bsc#1107616)

  - CVE-2018-16640: Prevent memory leak in the function ReadOneJNGImage
  (bsc#1107619)

  - CVE-2018-16641: Prevent memory leak in the TIFFWritePhotoshopLayers
  function (bsc#1107618).

  - CVE-2018-16643: The functions ReadDCMImage, ReadPWPImage, ReadCALSImage,
  and ReadPICTImage did check the return value of the fputc function,
  which allowed remote attackers to cause a denial of service via a
  crafted image file (bsc#1107612)

  - CVE-2018-16644: Added missing check for length in the functions
  ReadDCMImage and ReadPICTImage, which allowed remote attackers to cause
  a denial of service via a crafted image (bsc#1107609)

  - CVE-2018-16645: Prevent excessive memory allocation issue in the
  functions ReadBMPImage and ReadDIBImage, which allowed remote attackers
  to cause a denial
  of service via a crafted image file (bsc#1107604)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1108=1" );
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
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel", rpm: "ImageMagick-devel~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra", rpm: "ImageMagick-extra~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra-debuginfo", rpm: "ImageMagick-extra-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4", rpm: "libMagick++-7_Q16HDRI4~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-debuginfo", rpm: "libMagick++-7_Q16HDRI4-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel", rpm: "libMagick++-devel~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6", rpm: "libMagickCore-7_Q16HDRI6~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6", rpm: "libMagickWand-7_Q16HDRI6~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick", rpm: "perl-PerlMagick~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick-debuginfo", rpm: "perl-PerlMagick-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-doc", rpm: "ImageMagick-doc~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel-32bit", rpm: "ImageMagick-devel-32bit~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit", rpm: "libMagick++-7_Q16HDRI4-32bit~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit-debuginfo", rpm: "libMagick++-7_Q16HDRI4-32bit-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel-32bit", rpm: "libMagick++-devel-32bit~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit", rpm: "libMagickCore-7_Q16HDRI6-32bit~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit", rpm: "libMagickWand-7_Q16HDRI6-32bit~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
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

