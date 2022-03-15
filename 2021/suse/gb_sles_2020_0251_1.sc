if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0251.1" );
	script_cve_id( "CVE-2018-15869" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:09 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0251-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0251-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200251-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aws-cli' package(s) announced via the SUSE-SU-2020:0251-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for aws-cli to version 1.16.297 fixes the following issues:

Security issue fixed:
CVE-2018-15869: Fixed an permission handling issue where an unexpected
 AMI could potentially be used (bsc#1105988).

Non-security issues fixed:
Fixed an issue with the CLI client, where a ModuleNotFoundError was
 triggered (bsc#1092493)." );
	script_tag( name: "affected", value: "'aws-cli' package(s) on HPE Helion Openstack 8, SUSE Linux Enterprise Module for Public Cloud 12, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
	if(!isnull( res = isrpmvuln( pkg: "aws-cli", rpm: "aws-cli~1.16.297~22.11.1", rls: "SLES12.0" ) )){
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

