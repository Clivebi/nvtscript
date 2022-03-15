if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2465.1" );
	script_cve_id( "CVE-2017-13758", "CVE-2017-18271", "CVE-2018-10805", "CVE-2018-11251", "CVE-2018-12599", "CVE-2018-12600", "CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:38 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-09 11:05:00 +0000 (Thu, 09 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2465-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2465-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182465-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:2465-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:
Security issues fixed:
- CVE-2018-11251: Heap-based buffer over-read in ReadSUNImage in
 coders/sun.c, which allows attackers to cause denial of service
 (bsc#1094237)
- CVE-2017-18271: Infinite loop in the function ReadMIFFImage in
 coders/miff.c, which allows attackers to cause a denial of service
 (bsc#1094204)
- CVE-2017-13758: Heap-based buffer overflow in the TracePoint() in
 MagickCore/draw.c, which allows attackers to cause a denial of
 service(bsc#1056277)
- CVE-2018-10805: Fixed several memory leaks in rgb.c, cmyk.c, gray.c, and
 ycbcr.c (bsc#1095812)
- CVE-2018-12600: The ReadDIBImage and WriteDIBImage functions allowed
 attackers to cause an out of bounds write via a crafted file
 (bsc#1098545)
- CVE-2018-12599: The ReadBMPImage and WriteBMPImage fucntions allowed
 attackers to cause an out of bounds write via a crafted file
 (bsc#1098546)
- CVE-2018-14434: Fixed a memory leak for a colormap in WriteMPCImage in
 coders/mpc.c (bsc#1102003)
- CVE-2018-14435: Fixed a memory leak in DecodeImage in coders/pcd.c
 (bsc#1102007)
- CVE-2018-14436: Fixed a memory leak in ReadMIFFImage in coders/miff.c
 (bsc#1102005)
- CVE-2018-14437: Fixed a memory leak in parse8BIM in coders/meta.c
 (bsc#1102004)" );
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
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1-32bit", rpm: "libMagickCore1-32bit~6.4.3.6~78.56.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1", rpm: "libMagickCore1~6.4.3.6~78.56.1", rls: "SLES11.0SP4" ) )){
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

