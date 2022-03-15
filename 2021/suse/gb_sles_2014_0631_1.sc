if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0631.1" );
	script_cve_id( "CVE-2014-2583" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-03 15:01:00 +0000 (Thu, 03 Jan 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0631-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0631-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140631-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam' package(s) announced via the SUSE-SU-2014:0631-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update changes the broken default behavior of pam_pwhistory to not enforce checks when the root user requests password changes. In order to enforce pwhistory checks on the root user, the 'enforce_for_root' parameter needs to be set for the pam_pwhistory.so module.

This pam update fixes the following security and non-security issues:

 * bnc#870433: Fixed pam_timestamp path injection problem (CVE-2014-2583)
 * bnc#848417: Fixed pam_pwhistory root password enforcement when resetting non-root user's password

Security Issue references:

 * CVE-2014-2583
>" );
	script_tag( name: "affected", value: "'pam' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "pam", rpm: "pam~1.1.5~0.12.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam-32bit", rpm: "pam-32bit~1.1.5~0.12.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam-doc", rpm: "pam-doc~1.1.5~0.12.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam-x86", rpm: "pam-x86~1.1.5~0.12.1", rls: "SLES11.0SP3" ) )){
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

