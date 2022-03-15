if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1749.1" );
	script_cve_id( "CVE-2018-20340", "CVE-2019-12209", "CVE-2019-12210", "CVE-2019-9578" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1749-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1749-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191749-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libu2f-host' package(s) announced via the SUSE-SU-2019:1749-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libu2f-host and pam_u2f to version 1.0.8 fixes the following issues:

Security issues fixed for libu2f-host:
CVE-2019-9578: Fixed a memory leak due to a wrong parse of init's
 response (bsc#1128140).

CVE-2018-20340: Fixed an unchecked buffer, which could allow a buffer
 overflow with a custom made malicious USB device (bsc#1124781).

Security issues fixed for pam_u2f:
CVE-2019-12209: Fixed an issue where symlinks in the user's directory
 were followed (bsc#1135729).

CVE-2019-12210: Fixed file descriptor leaks (bsc#1135727)." );
	script_tag( name: "affected", value: "'libu2f-host' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libu2f-host-debugsource", rpm: "libu2f-host-debugsource~1.1.6~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libu2f-host0", rpm: "libu2f-host0~1.1.6~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libu2f-host0-debuginfo", rpm: "libu2f-host0-debuginfo~1.1.6~3.5.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_u2f", rpm: "pam_u2f~1.0.8~3.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_u2f-debuginfo", rpm: "pam_u2f-debuginfo~1.0.8~3.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_u2f-debugsource", rpm: "pam_u2f-debugsource~1.0.8~3.3.1", rls: "SLES12.0SP4" ) )){
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

