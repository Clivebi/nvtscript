if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0600.1" );
	script_cve_id( "CVE-2021-20243", "CVE-2021-20244", "CVE-2021-20246" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 08:15:00 +0000 (Thu, 03 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0600-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0600-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210600-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2021:0600-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes the following issues:

_ CVE-2021-20243 [bsc#1182336]: Division by zero in GetResizeFilterWeight in MagickCore/resize.c _ CVE-2021-20244 [bsc#1182325]: Division by zero in ImplodeImage in MagickCore/visual-effects.c _ CVE-2021-20246
[bsc#1182337]: Division by zero in ScaleResampleFilter in MagickCore/resample.c" );
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
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-6-SUSE", rpm: "ImageMagick-config-6-SUSE~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-config-6-upstream", rpm: "ImageMagick-config-6-upstream~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debugsource", rpm: "ImageMagick-debugsource~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1", rpm: "libMagickCore-6_Q16-1~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore-6_Q16-1-debuginfo", rpm: "libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1", rpm: "libMagickWand-6_Q16-1~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickWand-6_Q16-1-debuginfo", rpm: "libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.162.1", rls: "SLES12.0SP5" ) )){
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

