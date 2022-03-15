if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2676.1" );
	script_cve_id( "CVE-2015-8668", "CVE-2016-5319", "CVE-2017-17942", "CVE-2018-10779" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2676-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2676-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182676-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2018:2676-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tiff fixes the following issues:

The following security vulnerabilities were addressed:
CVE-2015-8668: Fixed a heap-based buffer overflow in the
 PackBitsPreEncode function in tif_packbits.c in bmp2tiff, which allowed
 remote attackers to execute arbitrary code or cause a denial of service
 via a large width field in a specially crafted BMP image. (bsc#960589)

CVE-2018-10779: Fixed a heap-based buffer over-read in
 TIFFWriteScanline() in tif_write.c (bsc#1092480)

CVE-2017-17942: Fixed a heap-based buffer overflow in the function
 PackBitsEncode in tif_packbits.c. (bsc#1074186)

CVE-2016-5319: Fixed a beap-based buffer overflow in bmp2tiff
 (bsc#983440)" );
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
	if(!isnull( res = isrpmvuln( pkg: "libtiff3", rpm: "libtiff3~3.8.2~141.169.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff3-32bit", rpm: "libtiff3-32bit~3.8.2~141.169.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff3-x86", rpm: "libtiff3-x86~3.8.2~141.169.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~3.8.2~141.169.16.1", rls: "SLES11.0SP4" ) )){
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

