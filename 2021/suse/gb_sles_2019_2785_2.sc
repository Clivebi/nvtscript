if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2785.2" );
	script_cve_id( "CVE-2019-14980", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-15141", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16712", "CVE-2019-16713" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-03 12:15:00 +0000 (Fri, 03 Jul 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2785-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2785-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192785-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2019:2785-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

Security issues fixed:
CVE-2019-15139: Fixed a denial-of-service vulnerability in ReadXWDImage.
 (bsc#1146213)

CVE-2019-15140: Fixed a use-after-free bug in the Matlab image parser.
 (bsc#1146212)

CVE-2019-15141: Fixed a divide-by-zero vulnerability in the
 MeanShiftImage function. (bsc#1146211)

CVE-2019-14980: Fixed an application crash resulting from a heap-based
 buffer over-read in WriteTIFFImage. (bsc#1146068)

CVE-2019-16708: Fixed a memory leak in magick/xwindow.c (bsc#1151781).

CVE-2019-16709: Fixed a memory leak in coders/dps.c (bsc#1151782).

CVE-2019-16710: Fixed a memory leak in coders/dot.c (bsc#1151783).

CVE-2019-16711: Fixed a memory leak in Huffman2DEncodeImage in
 coders/ps2.c (bsc#1151784).

CVE-2019-16712: Fixed a memory leak in Huffman2DEncodeImage in
 coders/ps3.c (bsc#1151785).

CVE-2019-16713: Fixed a memory leak in coders/dot.c (bsc#1151786)." );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-6-SUSE", rpm: "ImageMagick-config-6-SUSE~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-6-upstream", rpm: "ImageMagick-config-6-upstream~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1", rpm: "libMagickCore-6_Q16-1~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1-debuginfo", rpm: "libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1", rpm: "libMagickWand-6_Q16-1~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1-debuginfo", rpm: "libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.131.1", rls: "SLES12.0SP5" ) )){
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

