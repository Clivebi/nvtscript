if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0607.1" );
	script_cve_id( "CVE-2020-28493" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:43 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 07:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0607-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0607-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210607-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-Jinja2' package(s) announced via the SUSE-SU-2021:0607-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-Jinja2 fixes the following issues:

CVE-2020-28493: Improve the speed of the 'urlize' filter by reducing
 regex backtracking. Email matching requires a word character at the
 start of the domain part, and only word characters in the TLD.
 (bsc#1181944)" );
	script_tag( name: "affected", value: "'python-Jinja2' package(s) on SUSE Linux Enterprise Module for Advanced Systems Management 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Manager Tools 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-Jinja2", rpm: "python-Jinja2~2.8~19.23.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-Jinja2", rpm: "python3-Jinja2~2.8~19.23.1", rls: "SLES12.0" ) )){
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

