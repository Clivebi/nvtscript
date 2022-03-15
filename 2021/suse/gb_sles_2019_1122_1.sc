if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1122.1" );
	script_cve_id( "CVE-2018-19636", "CVE-2018-19637", "CVE-2018-19638", "CVE-2018-19639", "CVE-2018-19640" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 21:29:00 +0000 (Wed, 08 May 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1122-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1122-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191122-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hostinfo, supportutils' package(s) announced via the SUSE-SU-2019:1122-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for hostinfo, supportutils fixes the following issues:

Security issues fixed for supportutils:
CVE-2018-19640: Fixed an issue where users could kill arbitrary
 processes (bsc#1118463).

CVE-2018-19638: Fixed an issue where users could overwrite arbitrary log
 files (bsc#1118460).

CVE-2018-19639: Fixed a code execution if run with -v (bsc#1118462).

CVE-2018-19637: Fixed an issue where static temporary filename could
 allow overwriting of files (bsc#1117776).

CVE-2018-19636: Fixed a local root exploit via inclusion of attacker
 controlled shell script (bsc#1117751).

Other issues fixed for supportutils:
Fixed invalid exit code commands (bsc#1125666)

SUSE separation in supportconfig (bsc#1125623)

Clarified supportconfig(8) -x option (bsc#1115245)

supportconfig: 3.0.127

btrfs filesystem usage

List products.d

Dump lsof errors

Added ha commands for corosync

Dumped find errors in ib_info

Issues fixed in hostinfo:
Removed extra kernel install dates (bsc#1099498)

Resolved network bond issue (bsc#1054979)" );
	script_tag( name: "affected", value: "'hostinfo, supportutils' package(s) on SUSE CaaS Platform ALL, SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "hostinfo", rpm: "hostinfo~1.0.1~19.5.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "supportutils", rpm: "supportutils~3.0~95.21.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "hostinfo", rpm: "hostinfo~1.0.1~19.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "supportutils", rpm: "supportutils~3.0~95.21.1", rls: "SLES12.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "hostinfo", rpm: "hostinfo~1.0.1~19.5.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "supportutils", rpm: "supportutils~3.0~95.21.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "hostinfo", rpm: "hostinfo~1.0.1~19.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "supportutils", rpm: "supportutils~3.0~95.21.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "hostinfo", rpm: "hostinfo~1.0.1~19.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "supportutils", rpm: "supportutils~3.0~95.21.1", rls: "SLES12.0SP4" ) )){
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

