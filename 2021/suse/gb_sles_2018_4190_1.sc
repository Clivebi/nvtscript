if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.4190.1" );
	script_cve_id( "CVE-2018-19486" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-11 03:29:00 +0000 (Thu, 11 Apr 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:4190-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:4190-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20184190-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'git' package(s) announced via the SUSE-SU-2018:4190-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for git fixes the following issues:

Security issue fixed:
CVE-2018-19486: Fixed git that executed commands from the current
 working directory (as if '.' were at the end of $PATH) in certain cases
 involving the run_command() API and run-command.c, because there was
 (bsc#1117257)." );
	script_tag( name: "affected", value: "'git' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "git-core", rpm: "git-core~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-core-debuginfo", rpm: "git-core-debuginfo~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-debuginfo", rpm: "git-debuginfo~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-debugsource", rpm: "git-debugsource~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git", rpm: "git~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-arch", rpm: "git-arch~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-cvs", rpm: "git-cvs~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-daemon", rpm: "git-daemon~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-daemon-debuginfo", rpm: "git-daemon-debuginfo~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-doc", rpm: "git-doc~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-email", rpm: "git-email~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-gui", rpm: "git-gui~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-svn", rpm: "git-svn~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-svn-debuginfo", rpm: "git-svn-debuginfo~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-web", rpm: "git-web~2.16.4~3.9.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gitk", rpm: "gitk~2.16.4~3.9.2", rls: "SLES15.0" ) )){
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

