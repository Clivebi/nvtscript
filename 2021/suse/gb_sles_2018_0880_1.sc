if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0880.1" );
	script_cve_id( "CVE-2017-11524", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-13768", "CVE-2017-14314", "CVE-2017-14343", "CVE-2017-14505", "CVE-2017-15016", "CVE-2017-15017", "CVE-2017-16352", "CVE-2017-16353", "CVE-2017-18219", "CVE-2017-9500", "CVE-2018-7443", "CVE-2018-8804" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:46 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-16 19:18:00 +0000 (Tue, 16 Apr 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0880-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0880-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180880-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0880-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes several issues.
These security issues were fixed:
- CVE-2018-8804: The WriteEPTImage function allowed remote attackers to
 cause a denial of service (double free and application crash) or
 possibly have unspecified other impact via a crafted file (bsc#1086011)
- CVE-2017-11524: The WriteBlob function allowed remote attackers to cause
 a denial of service (assertion failure and application exit) via a
 crafted file (bsc#1050087)
- CVE-2017-18219: Prevent allocation failure in the function
 ReadOnePNGImage, which allowed attackers to cause a denial of service
 via a crafted file that triggers an attempt at a large png_pixels array
 allocation (bsc#1084060).
- CVE-2017-9500: Prevent assertion failure in the function
 ResetImageProfileIterator, which allowed attackers to cause a denial of
 service via a crafted file (bsc#1043290)
- CVE-2017-16353: Prevent memory information disclosure in the
 DescribeImage function caused by a heap-based buffer over-read. The
 portion of the code containing the vulnerability is responsible for
 printing the IPTC Profile information contained in the image. This
 vulnerability can be triggered with a specially crafted MIFF file. There
 is an out-of-bounds buffer dereference because certain increments were
 never checked (bsc#1066170)
- CVE-2017-16352: Prevent a heap-based buffer overflow in the 'Display
 visual image directory' feature of the DescribeImage() function. One
 possible way to trigger the vulnerability is to run the identify command
 on a specially crafted MIFF format file with the verbose flag
 (bsc#1066168)
- CVE-2017-14314: Prevent off-by-one error in the DrawImage function that
 allowed remote attackers to cause a denial of service (DrawDashPolygon
 heap-based buffer over-read and application crash) via a crafted file
 (bsc#1058630)
- CVE-2017-13768: Prevent NULL pointer dereference in the IdentifyImage
 function that allowed an attacker to perform denial of service by
 sending a crafted image file (bsc#1056434)
- CVE-2017-14505: Fixed handling of NULL arrays, which allowed attackers
 to perform Denial of Service (NULL pointer dereference and application
 crash in AcquireQuantumMemory within MagickCore/memory.c) by providing a
 crafted Image File as input (bsc#1059735)
- CVE-2018-7443: The ReadTIFFImage function did not properly validate the
 amount of image data in a file, which allowed remote attackers to cause
 a denial of service (memory allocation failure in the
 AcquireMagickMemory function in MagickCore/memory.c) (bsc#1082792)
- CVE-2017-15016: Prevent NULL pointer dereference vulnerability in
 ReadEnhMetaFile allowing for denial of service (bsc#1082291)
- CVE-2017-15017: Prevent NULL pointer dereference vulnerability in
 ReadOneMNGImage allowing for denial of service (bsc#1082283)
- CVE-2017-12692: The ReadVIFFImage function allowed remote attackers to
 cause a denial of service (memory ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1-32bit", rpm: "libMagickCore1-32bit~6.4.3.6~78.40.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1", rpm: "libMagickCore1~6.4.3.6~78.40.1", rls: "SLES11.0SP4" ) )){
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

