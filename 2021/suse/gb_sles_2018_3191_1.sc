if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3191.1" );
	script_cve_id( "CVE-2017-13058", "CVE-2018-12599", "CVE-2018-12600", "CVE-2018-17965", "CVE-2018-17966", "CVE-2018-18016", "CVE-2018-18024" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-09 11:05:00 +0000 (Thu, 09 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3191-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3191-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183191-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:3191-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

Security issues fixed:
CVE-2018-18024: Fixed an infinite loop in the ReadBMPImage function of
 the coders/bmp.c file. Remote attackers could leverage this
 vulnerability to cause a denial of service via a crafted bmp file.
 (bsc#1111069)

CVE-2018-18016: Fixed a memory leak in WritePCXImage (bsc#1111072).

CVE-2018-17965: Fixed a memory leak in WriteSGIImage (bsc#1110747).

CVE-2018-17966: Fixed a memory leak in WritePDBImage (bsc#1110746).

CVE-2018-12600: ReadDIBImage and WriteDIBImage allowed attackers to
 cause an out of bounds write via a crafted file. (bsc#1098545)

CVE-2018-12599: ReadBMPImage and WriteBMPImage allowed attackers to
 cause an out of bounds write via a crafted file. (bsc#1098546)" );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~6.8.8.1~71.82.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~6.8.8.1~71.82.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1", rpm: "libMagickCore-6_Q16-1~6.8.8.1~71.82.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1-debuginfo", rpm: "libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.82.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1", rpm: "libMagickWand-6_Q16-1~6.8.8.1~71.82.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1-debuginfo", rpm: "libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.82.1", rls: "SLES12.0SP3" ) )){
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

