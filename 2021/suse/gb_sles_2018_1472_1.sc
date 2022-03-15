if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1472.1" );
	script_cve_id( "CVE-2016-10267", "CVE-2016-10269", "CVE-2016-10270", "CVE-2016-5314", "CVE-2016-5315", "CVE-2017-18013", "CVE-2017-7593", "CVE-2017-7595", "CVE-2017-7596", "CVE-2017-7597", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601", "CVE-2017-7602" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:44 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-05 16:56:00 +0000 (Thu, 05 Apr 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1472-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1472-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181472-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2018:1472-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tiff fixes the following issues:
Security issues fixed:
- CVE-2016-5315: The setByteArray function in tif_dir.c allowed remote
 attackers to cause a denial of service (out-of-bounds read) via a
 crafted tiff image. (bsc#984809)
- CVE-2016-10267: LibTIFF allowed remote attackers to cause a denial of
 service (divide-by-zero error and application crash) via a crafted TIFF
 image, related to libtiff/tif_ojpeg.c:816:8. (bsc#1017694)
- CVE-2016-10269: LibTIFF allowed remote attackers to cause a denial of
 service (heap-based buffer over-read) or possibly have unspecified other
 impact via a crafted TIFF image, related to 'READ of size 512' and
 libtiff/tif_unix.c:340:2. (bsc#1031254)
- CVE-2016-10270: LibTIFF allowed remote attackers to cause a denial of
 service (heap-based buffer over-read) or possibly have unspecified other
 impact via a crafted TIFF image, related to 'READ of size 8' and
 libtiff/tif_read.c:523:22. (bsc#1031250)
- CVE-2017-18013: In LibTIFF, there was a Null-Pointer Dereference in the
 tif_print.c TIFFPrintDirectory function, as demonstrated by a tiffinfo
 crash. (bsc#1074317)
- CVE-2017-7593: tif_read.c did not ensure that tif_rawdata is properly
 initialized, which might have allowed remote attackers to obtain
 sensitive information from process memory via a crafted image.
 (bsc#1033129)
- CVE-2017-7595: The JPEGSetupEncode function in tiff_jpeg.c allowed
 remote attackers to cause a denial of service (divide-by-zero error and
 application crash) via a crafted image. (bsc#1033127)
- CVE-2017-7596: LibTIFF had an 'outside the range of representable values
 of type float' undefined behavior issue, which might have allowed remote
 attackers to cause a denial of service (application crash) or possibly
 have unspecified other impact via a crafted image. (bsc#1033126)
- CVE-2017-7597: tif_dirread.c had an 'outside the range of representable
 values of type float' undefined behavior issue, which might have allowed
 remote attackers to cause a denial of service (application crash) or
 possibly have unspecified other impact via a crafted image.
 (bsc#1033120)
- CVE-2017-7599: LibTIFF had an 'outside the range of representable values
 of type short' undefined behavior issue, which might have allowed remote
 attackers to cause a denial of service (application crash) or possibly
 have unspecified other impact via a crafted image. (bsc#1033113)
- CVE-2017-7600: LibTIFF had an 'outside the range of representable values
 of type unsigned char' undefined behavior issue, which might have
 allowed remote attackers to cause a denial of service (application
 crash) or possibly have unspecified other impact via a crafted image.
 (bsc#1033112)
- CVE-2017-7601: LibTIFF had a 'shift exponent too large for 64-bit type
 long' undefined behavior issue, which might have allowed remote
 attackers to cause a denial of service (application crash) or possibly
 have ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'tiff' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libtiff3", rpm: "libtiff3~3.8.2~141.169.6.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff3-32bit", rpm: "libtiff3-32bit~3.8.2~141.169.6.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff3-x86", rpm: "libtiff3-x86~3.8.2~141.169.6.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~3.8.2~141.169.6.1", rls: "SLES11.0SP4" ) )){
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

