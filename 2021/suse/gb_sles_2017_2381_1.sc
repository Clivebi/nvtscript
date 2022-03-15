if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2381.1" );
	script_cve_id( "CVE-2017-2862", "CVE-2017-2870", "CVE-2017-6312", "CVE-2017-6313", "CVE-2017-6314" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 02:29:00 +0000 (Wed, 08 Nov 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2381-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2381-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172381-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdk-pixbuf' package(s) announced via the SUSE-SU-2017:2381-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gdk-pixbuf fixes the following issues:
- CVE-2017-2862: JPEG gdk_pixbuf__jpeg_image_load_increment Code Execution
 Vulnerability (bsc#1048289)
- CVE-2017-2870: tiff_image_parse Code Execution Vulnerability
 (bsc#1048544)
- CVE-2017-6313: A dangerous integer underflow in io-icns.c (bsc#1027024)
- CVE-2017-6314: Infinite loop in io-tiff.c (bsc#1027025)
- CVE-2017-6312: Out-of-bounds read on io-ico.c (bsc#1027026)" );
	script_tag( name: "affected", value: "'gdk-pixbuf' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-debugsource", rpm: "gdk-pixbuf-debugsource~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-lang", rpm: "gdk-pixbuf-lang~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders", rpm: "gdk-pixbuf-query-loaders~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-32bit", rpm: "gdk-pixbuf-query-loaders-32bit~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-debuginfo", rpm: "gdk-pixbuf-query-loaders-debuginfo~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-debuginfo-32bit", rpm: "gdk-pixbuf-query-loaders-debuginfo-32bit~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0", rpm: "libgdk_pixbuf-2_0-0~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-32bit", rpm: "libgdk_pixbuf-2_0-0-32bit~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-debuginfo", rpm: "libgdk_pixbuf-2_0-0-debuginfo~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-debuginfo-32bit", rpm: "libgdk_pixbuf-2_0-0-debuginfo-32bit~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GdkPixbuf-2_0", rpm: "typelib-1_0-GdkPixbuf-2_0~2.34.0~19.5.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-debugsource", rpm: "gdk-pixbuf-debugsource~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-lang", rpm: "gdk-pixbuf-lang~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders", rpm: "gdk-pixbuf-query-loaders~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-32bit", rpm: "gdk-pixbuf-query-loaders-32bit~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-debuginfo", rpm: "gdk-pixbuf-query-loaders-debuginfo~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-debuginfo-32bit", rpm: "gdk-pixbuf-query-loaders-debuginfo-32bit~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0", rpm: "libgdk_pixbuf-2_0-0~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-32bit", rpm: "libgdk_pixbuf-2_0-0-32bit~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-debuginfo", rpm: "libgdk_pixbuf-2_0-0-debuginfo~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-debuginfo-32bit", rpm: "libgdk_pixbuf-2_0-0-debuginfo-32bit~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GdkPixbuf-2_0", rpm: "typelib-1_0-GdkPixbuf-2_0~2.34.0~19.5.1", rls: "SLES12.0SP3" ) )){
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

