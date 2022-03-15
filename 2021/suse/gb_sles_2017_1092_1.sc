if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1092.1" );
	script_cve_id( "CVE-2017-7467" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1092-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1092-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171092-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'minicom' package(s) announced via the SUSE-SU-2017:1092-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for minicom fixes the following issue:
This security issue was fixed:
- CVE-2017-7467: Invalid cursor coordinates and scroll regions could lead
 to code execution (bsc#1033783)." );
	script_tag( name: "affected", value: "'minicom' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "minicom", rpm: "minicom~2.7~3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "minicom-debuginfo", rpm: "minicom-debuginfo~2.7~3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "minicom-debugsource", rpm: "minicom-debugsource~2.7~3.1", rls: "SLES12.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "minicom", rpm: "minicom~2.7~3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "minicom-debuginfo", rpm: "minicom-debuginfo~2.7~3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "minicom-debugsource", rpm: "minicom-debugsource~2.7~3.1", rls: "SLES12.0SP2" ) )){
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

