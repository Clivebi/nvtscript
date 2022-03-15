if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2649.1" );
	script_cve_id( "CVE-2016-10507", "CVE-2017-14039", "CVE-2017-14040", "CVE-2017-14041", "CVE-2017-14164" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 19:55:00 +0000 (Tue, 02 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2649-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2649-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172649-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2' package(s) announced via the SUSE-SU-2017:2649-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openjpeg2 fixes several issues.
These security issues were fixed:
- CVE-2016-10507: Integer overflow vulnerability in the bmp24toimage
 function allowed remote attackers to cause a denial of service
 (heap-based buffer
 over-read and application crash) via a crafted bmp file (bsc#1056421).
- CVE-2017-14039: A heap-based buffer overflow was discovered in the
 opj_t2_encode_packet function. The vulnerability caused an out-of-bounds
 write, which may have lead to remote denial of service or possibly
 unspecified other impact (bsc#1056622).
- CVE-2017-14164: A size-validation issue was discovered in
 opj_j2k_write_sot. The vulnerability caused an out-of-bounds write,
 which may have lead to remote DoS or possibly remote code execution
 (bsc#1057511).
- CVE-2017-14040: An invalid write access was discovered in
 bin/jp2/convert.c, triggering a crash in the tgatoimage function. The
 vulnerability may have lead to remote denial of service or possibly
 unspecified other impact (bsc#1056621).
- CVE-2017-14041: A stack-based buffer overflow was discovered in the
 pgxtoimage function. The vulnerability caused an out-of-bounds write,
 which may have lead to remote denial of service or possibly remote code
 execution (bsc#1056562)." );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7", rpm: "libopenjp2-7~2.1.0~4.6.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7-debuginfo", rpm: "libopenjp2-7-debuginfo~2.1.0~4.6.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debuginfo", rpm: "openjpeg2-debuginfo~2.1.0~4.6.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debugsource", rpm: "openjpeg2-debugsource~2.1.0~4.6.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7", rpm: "libopenjp2-7~2.1.0~4.6.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenjp2-7-debuginfo", rpm: "libopenjp2-7-debuginfo~2.1.0~4.6.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debuginfo", rpm: "openjpeg2-debuginfo~2.1.0~4.6.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2-debugsource", rpm: "openjpeg2-debugsource~2.1.0~4.6.1", rls: "SLES12.0SP3" ) )){
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

