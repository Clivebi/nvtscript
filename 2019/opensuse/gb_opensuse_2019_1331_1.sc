if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852474" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-10650", "CVE-2019-11007", "CVE-2019-11008", "CVE-2019-9956" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-05 02:00:41 +0000 (Sun, 05 May 2019)" );
	script_name( "openSUSE: Security Advisory for ImageMagick (openSUSE-SU-2019:1331-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1331-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00010.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the openSUSE-SU-2019:1331-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

  Security issues fixed:

  - CVE-2019-9956: Fixed a stack-based buffer overflow in PopHexPixel()
  (bsc#1130330).

  - CVE-2019-10650: Fixed a heap-based buffer over-read in WriteTIFFImage()
  (bsc#1131317).

  - CVE-2019-11007: Fixed a heap-based buffer overflow in ReadMNGImage()
  (bsc#1132060).

  - CVE-2019-11008: Fixed a heap-based buffer overflow in WriteXWDImage()
  (bsc#1132054).

  - Added extra -config- packages with Postscript/EPS/PDF readers still
  enabled.

  Removing the PS decoders is used to harden ImageMagick against security
  issues within ghostscript. Enabling them might impact security.
  (bsc#1122033)

  These are two packages that can be selected:

  - ImageMagick-config-7-SUSE: This has the PS decoders disabled.

  - ImageMagick-config-7-upstream: This has the PS decoders enabled.

  Depending on your local needs install either one of them. The default is
  the -SUSE configuration.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1331=1" );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-7-SUSE", rpm: "ImageMagick-config-7-SUSE~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-7-upstream", rpm: "ImageMagick-config-7-upstream~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel", rpm: "ImageMagick-devel~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra", rpm: "ImageMagick-extra~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-extra-debuginfo", rpm: "ImageMagick-extra-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4", rpm: "libMagick++-7_Q16HDRI4~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-debuginfo", rpm: "libMagick++-7_Q16HDRI4-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel", rpm: "libMagick++-devel~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6", rpm: "libMagickCore-7_Q16HDRI6~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6", rpm: "libMagickWand-7_Q16HDRI6~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick", rpm: "perl-PerlMagick~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-PerlMagick-debuginfo", rpm: "perl-PerlMagick-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-doc", rpm: "ImageMagick-doc~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel-32bit", rpm: "ImageMagick-devel-32bit~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit", rpm: "libMagick++-7_Q16HDRI4-32bit~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-7_Q16HDRI4-32bit-debuginfo", rpm: "libMagick++-7_Q16HDRI4-32bit-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagick++-devel-32bit", rpm: "libMagick++-devel-32bit~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit", rpm: "libMagickCore-7_Q16HDRI6-32bit~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickCore-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit", rpm: "libMagickWand-7_Q16HDRI6-32bit~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-7_Q16HDRI6-32bit-debuginfo", rpm: "libMagickWand-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~lp150.2.29.1", rls: "openSUSELeap15.0" ) )){
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

