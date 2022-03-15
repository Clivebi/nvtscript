if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3184.2" );
	script_cve_id( "CVE-2018-13301", "CVE-2019-12730", "CVE-2019-17542", "CVE-2019-9718" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:00 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3184-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3184-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193184-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ffmpeg' package(s) announced via the SUSE-SU-2019:3184-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ffmpeg fixes the following issues:

Security issues fixed:
CVE-2019-17542: Fixed a heap-buffer overflow in vqa_decode_chunk due to
 an
 out-of-array access (bsc#1154064).

CVE-2019-12730: Fixed an uninitialized use of variables due to an
 improper check (bsc#1137526).

CVE-2019-9718: Fixed a denial of service in the subtitle decode
 (bsc#1129715).

CVE-2018-13301: Fixed a denial of service while converting a crafted AVI
 file to MPEG4 (bsc#1100352)." );
	script_tag( name: "affected", value: "'ffmpeg' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "ffmpeg", rpm: "ffmpeg~3.4.2~4.27.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ffmpeg-debuginfo", rpm: "ffmpeg-debuginfo~3.4.2~4.27.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ffmpeg-debugsource", rpm: "ffmpeg-debugsource~3.4.2~4.27.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavdevice57", rpm: "libavdevice57~3.4.2~4.27.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavdevice57-debuginfo", rpm: "libavdevice57-debuginfo~3.4.2~4.27.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavfilter6", rpm: "libavfilter6~3.4.2~4.27.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavfilter6-debuginfo", rpm: "libavfilter6-debuginfo~3.4.2~4.27.1", rls: "SLES15.0SP1" ) )){
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

