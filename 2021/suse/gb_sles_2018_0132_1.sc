if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0132.1" );
	script_cve_id( "CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-10800", "CVE-2017-11141", "CVE-2017-11449", "CVE-2017-11529", "CVE-2017-11644", "CVE-2017-11724", "CVE-2017-11751", "CVE-2017-12430", "CVE-2017-12434", "CVE-2017-12564", "CVE-2017-12642", "CVE-2017-12667", "CVE-2017-12670", "CVE-2017-12672", "CVE-2017-12675", "CVE-2017-13060", "CVE-2017-13146", "CVE-2017-13648", "CVE-2017-13658", "CVE-2017-14249", "CVE-2017-14326", "CVE-2017-14533", "CVE-2017-17680", "CVE-2017-17881", "CVE-2017-17882", "CVE-2017-18022", "CVE-2017-9409", "CVE-2018-5246", "CVE-2018-5247" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-20 15:37:00 +0000 (Tue, 20 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0132-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0132-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180132-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0132-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ImageMagick fixes several issues.
These security issues were fixed:
- CVE-2017-12672: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service (bsc#1052720).
- CVE-2017-13060: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service via a crafted file (bsc#1055065).
- CVE-2017-11724: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c involving the quantum_info and clone_info
 data structures (bsc#1051446).
- CVE-2017-12670: Added validation in coders/mat.c to prevent an assertion
 failure in the function DestroyImage in MagickCore/image.c, which
 allowed attackers to cause a denial of service (bsc#1052731).
- CVE-2017-12667: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c (bsc#1052732).
- CVE-2017-13146: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c (bsc#1055323).
- CVE-2017-10800: Processing MATLAB images in coders/mat.c could have lead
 to a denial of service (OOM) in ReadMATImage() if the size specified for
 a MAT Object was larger than the actual amount of data (bsc#1047044)
- CVE-2017-13648: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c (bsc#1055434).
- CVE-2017-11141: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders\\mat.c that could have caused memory exhaustion
 via a crafted MAT file, related to incorrect ordering of a
 SetImageExtent call (bsc#1047898).
- CVE-2017-11529: The ReadMATImage function in coders/mat.c allowed remote
 attackers to cause a denial of service (memory leak) via a crafted file
 (bsc#1050120).
- CVE-2017-12564: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service (bsc#1052468).
- CVE-2017-12434: Added a missing NULL check in the function ReadMATImage
 in coders/mat.c, which allowed attackers to cause a denial of service
 (assertion failure) in DestroyImageInfo in image.c (bsc#1052550).
- CVE-2017-12675: Added a missing check for multidimensional data
 coders/mat.c, that could have lead to a memory leak in the function
 ReadImage in MagickCore/constitute.c, which allowed attackers to cause a
 denial of service (bsc#1052710).
- CVE-2017-14326: Fixed a memory leak vulnerability in the function
 ReadMATImage in coders/mat.c, which allowed attackers to cause a denial
 of service via a crafted file (bsc#1058640).
- CVE-2017-11644: Processesing a crafted file in convert could have lead
 to a memory leak in the ReadMATImage() function in coders/mat.c
 (bsc#1050606).
- CVE-2017-13658: Added a missing NULL check in the ReadMATImage function
 in coders/mat.c, which could have lead to a denial of service (assertion
 failure and application exit) in the ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1-32bit", rpm: "libMagickCore1-32bit~6.4.3.6~7.78.22.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1", rpm: "libMagickCore1~6.4.3.6~7.78.22.1", rls: "SLES11.0SP4" ) )){
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

