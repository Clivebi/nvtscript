if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.3301.1" );
	script_cve_id( "CVE-2014-8127", "CVE-2016-3622", "CVE-2016-3658", "CVE-2016-5321", "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9448", "CVE-2016-9453" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-31 18:57:00 +0000 (Tue, 31 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:3301-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:3301-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20163301-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2016:3301-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The tiff library and tools were updated to version 4.0.7 fixing various bug and security issues.
- CVE-2014-8127: out-of-bounds read with malformed TIFF image in multiple
 tools [bnc#914890]
- CVE-2016-9297: tif_dirread.c read outside buffer in _TIFFPrintField()
 [bnc#1010161]
- CVE-2016-3658: Illegal read in TIFFWriteDirectoryTagLongLong8Array
 function in tiffset / tif_dirwrite.c [bnc#974840]
- CVE-2016-9273: heap overflow [bnc#1010163]
- CVE-2016-3622: divide By Zero in the tiff2rgba tool [bnc#974449]
- CVE-2016-5652: tiff2pdf JPEG Compression Tables Heap Buffer Overflow
 [bnc#1007280]
- CVE-2016-9453: out-of-bounds Write memcpy and less bound check in
 tiff2pdf [bnc#1011107]
- CVE-2016-5875: heap-based buffer overflow when using the PixarLog
 compressionformat [bnc#987351]
- CVE-2016-9448: regression introduced by fixing CVE-2016-9297
 [bnc#1011103]
- CVE-2016-5321: out-of-bounds read in tiffcrop / DumpModeDecode()
 function [bnc#984813]
- CVE-2016-5323: Divide-by-zero in _TIFFFax3fillruns() function (null ptr
 dereference?) [bnc#984815]" );
	script_tag( name: "affected", value: "'tiff' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-32bit", rpm: "libtiff5-32bit~4.0.7~35.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5", rpm: "libtiff5~4.0.7~35.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo-32bit", rpm: "libtiff5-debuginfo-32bit~4.0.7~35.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo", rpm: "libtiff5-debuginfo~4.0.7~35.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~4.0.7~35.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debuginfo", rpm: "tiff-debuginfo~4.0.7~35.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debugsource", rpm: "tiff-debugsource~4.0.7~35.1", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-32bit", rpm: "libtiff5-32bit~4.0.7~35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5", rpm: "libtiff5~4.0.7~35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo-32bit", rpm: "libtiff5-debuginfo-32bit~4.0.7~35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff5-debuginfo", rpm: "libtiff5-debuginfo~4.0.7~35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~4.0.7~35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debuginfo", rpm: "tiff-debuginfo~4.0.7~35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff-debugsource", rpm: "tiff-debugsource~4.0.7~35.1", rls: "SLES12.0SP2" ) )){
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

