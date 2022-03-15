if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.13993.1" );
	script_cve_id( "CVE-2018-16412", "CVE-2018-16413", "CVE-2018-18544", "CVE-2018-20467", "CVE-2019-7175", "CVE-2019-7397", "CVE-2019-7398" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:29 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:13993-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:13993-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201913993-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2019:13993-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

Security issues fixed:
CVE-2019-7175: Fixed multiple memory leaks in DecodeImage function
 (bsc#1128649).

CVE-2018-18544: Fixed memory leak in the function WriteMSLImage
 (bsc#1113064).

CVE-2018-20467: Fixed infinite loop in coders/bmp.c (bsc#1120381).

CVE-2019-7397: Fixed a memory leak in the function WritePDFImage
 (bsc#1124366).

CVE-2018-16413: Prevent heap-based buffer over-read in the
 PushShortPixel function leading to DoS (bsc#1106989).

CVE-2018-16412: Prevent heap-based buffer over-read in the
 ParseImageResourceBlocks function leading to DOS (bsc#1106996).

CVE-2019-7398: Fixed a memory leak in the function WriteDIBImage
 (bsc#1124365)." );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1-32bit", rpm: "libMagickCore1-32bit~6.4.3.6~78.92.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1", rpm: "libMagickCore1~6.4.3.6~78.92.1", rls: "SLES11.0SP4" ) )){
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

