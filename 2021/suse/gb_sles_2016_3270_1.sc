if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.3270.1" );
	script_cve_id( "CVE-2016-7445", "CVE-2016-8332", "CVE-2016-9112", "CVE-2016-9113", "CVE-2016-9114", "CVE-2016-9115", "CVE-2016-9116", "CVE-2016-9117", "CVE-2016-9118", "CVE-2016-9572", "CVE-2016-9573", "CVE-2016-9580", "CVE-2016-9581" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 19:57:00 +0000 (Wed, 09 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:3270-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:3270-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20163270-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2' package(s) announced via the SUSE-SU-2016:3270-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openjpeg2 fixes the following issues:
* CVE-2016-9114: NULL Pointer Access in function imagetopnm of
 convert.c:1943(jp2) could lead to crash [bsc#1007740]
* CVE-2016-9115: Heap Buffer Overflow in function imagetotga of
 convert.c(jp2) [bsc#1007741]
* CVE-2016-9580, CVE-2016-9581: Possible Heap buffer overflow via integer
 overflow and infite loop [bsc#1014975]
* CVE-2016-9117: NULL Pointer Access in function imagetopnm of
 convert.c(jp2):1289 [bsc#1007743]
* CVE-2016-9118: Heap Buffer Overflow in function pnmtoimage of convert.c
 [bsc#1007744]
* CVE-2016-9112: FPE(Floating Point Exception) in lib/openjp2/pi.c:523
 [bsc#1007747]
* CVE-2016-9116: NULL Pointer Access in function imagetopnm of
 convert.c:2226(jp2) [bsc#1007742]
* CVE-2016-9113: NULL point dereference in function imagetobmp of
 convertbmp.c could lead to crash [bsc#1007739]
* CVE-2016-9572 CVE-2016-9573: Insuficient check in imagetopnm() could
 lead to heap buffer overflow [bsc#1014543]
* CVE-2016-8332: Malicious file in OpenJPEG JPEG2000 format could lead to
 code execution [bsc#1002414]
* CVE-2016-7445: Null pointer dereference in convert.c could lead to crash
 [bsc#999817]" );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7", rpm: "libopenjp2-7~2.1.0~3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7-debuginfo", rpm: "libopenjp2-7-debuginfo~2.1.0~3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debuginfo", rpm: "openjpeg2-debuginfo~2.1.0~3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debugsource", rpm: "openjpeg2-debugsource~2.1.0~3.1", rls: "SLES12.0SP2" ) )){
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

