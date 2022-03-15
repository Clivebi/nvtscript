if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1163.1" );
	script_cve_id( "CVE-2019-3688", "CVE-2019-3690", "CVE-2020-8013" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-20 16:15:00 +0000 (Fri, 20 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1163-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1163-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201163-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'permissions' package(s) announced via the SUSE-SU-2020:1163-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for permissions fixes the following issues:

Security issue fixed:

CVE-2020-8013: Fixed a local privilege escalation with mrsh and wodim
 (bsc#1163922).

Non-security issues fixed:

Fixed regression where chkstat breaks without /proc available
 (bsc#1160764, bsc#1160594)

Fixed capability handling when doing multiple permission changes at once
 (bsc#1161779)

Fixed handling of relative directory symlinks in chkstat" );
	script_tag( name: "affected", value: "'permissions' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "permissions", rpm: "permissions~20180125~3.21.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debuginfo", rpm: "permissions-debuginfo~20180125~3.21.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debugsource", rpm: "permissions-debugsource~20180125~3.21.1", rls: "SLES15.0" ) )){
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

