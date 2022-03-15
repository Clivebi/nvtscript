if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3058.1" );
	script_cve_id( "CVE-2016-5102", "CVE-2018-17000", "CVE-2019-14973", "CVE-2019-6128", "CVE-2019-7663" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3058-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3058-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193058-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2019:3058-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tiff fixes the following issues:

Security issues fixed:
CVE-2019-14973: Fixed an improper check which was depended on the
 compiler which could have led to integer overflow (bsc#1146608).

CVE-2016-5102: Fixed a buffer overflow in readgifimage() (bsc#983268)

CVE-2018-17000: Fixed a NULL pointer dereference in the _TIFFmemcmp
 function (bsc#1108606).

CVE-2019-6128: Fixed a memory leak in the TIFFFdOpen function in
 tif_unix.c (bsc#1121626).

CVE-2019-7663: Fixed an invalid address dereference in the
 TIFFWriteDirectoryTagTransfer function in libtiff/tif_dirwrite.c
 (bsc#1125113)" );
	script_tag( name: "affected", value: "'tiff' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-32bit", rpm: "libtiff5-32bit~4.0.9~44.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5", rpm: "libtiff5~4.0.9~44.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo-32bit", rpm: "libtiff5-debuginfo-32bit~4.0.9~44.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo", rpm: "libtiff5-debuginfo~4.0.9~44.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~4.0.9~44.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debuginfo", rpm: "tiff-debuginfo~4.0.9~44.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debugsource", rpm: "tiff-debugsource~4.0.9~44.42.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-32bit", rpm: "libtiff5-32bit~4.0.9~44.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5", rpm: "libtiff5~4.0.9~44.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo-32bit", rpm: "libtiff5-debuginfo-32bit~4.0.9~44.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo", rpm: "libtiff5-debuginfo~4.0.9~44.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~4.0.9~44.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debuginfo", rpm: "tiff-debuginfo~4.0.9~44.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debugsource", rpm: "tiff-debugsource~4.0.9~44.42.1", rls: "SLES12.0SP5" ) )){
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

