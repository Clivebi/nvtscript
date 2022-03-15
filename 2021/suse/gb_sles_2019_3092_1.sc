if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3092.1" );
	script_cve_id( "CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2017-14501", "CVE-2017-14502", "CVE-2018-1000877", "CVE-2018-1000878", "CVE-2019-1000019", "CVE-2019-1000020", "CVE-2019-18408" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3092-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3092-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193092-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive' package(s) announced via the SUSE-SU-2019:3092-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libarchive fixes the following issues:

Security issues fixed:
CVE-2018-1000877: Fixed a double free vulnerability in RAR decoder
 (bsc#1120653).

CVE-2018-1000878: Fixed a Use-After-Free vulnerability in RAR decoder
 (bsc#1120654).

CVE-2019-1000019: Fixed an Out-Of-Bounds Read vulnerability in 7zip
 decompression (bsc#1124341).

CVE-2019-1000020: Fixed an Infinite Loop vulnerability in ISO9660 parser
 (bsc#1124342).

CVE-2019-18408: Fixed a use-after-free in RAR format support
 (bsc#1155079)." );
	script_tag( name: "affected", value: "'libarchive' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "libarchive-debugsource", rpm: "libarchive-debugsource~3.1.2~26.6.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13", rpm: "libarchive13~3.1.2~26.6.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13-debuginfo", rpm: "libarchive13-debuginfo~3.1.2~26.6.1", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libarchive-debugsource", rpm: "libarchive-debugsource~3.1.2~26.6.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13", rpm: "libarchive13~3.1.2~26.6.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13-debuginfo", rpm: "libarchive13-debuginfo~3.1.2~26.6.1", rls: "SLES12.0SP5" ) )){
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

