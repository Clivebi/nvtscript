if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850988" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 16:15:23 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2014-0475", "CVE-2014-6271" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for bash (SUSE-SU-2014:1212-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "bash has been updated to fix a critical security issue.

  In some circumstances, the shell would evaluate shellcode in environment
  variables passed at startup time. This allowed code execution by local or
  remote attackers who could pass environment variables to bash scripts.
  (CVE-2014-6271)

  Additionally, the following bugs have been fixed:

  * Fix crash when expanding '$[' without matching ']'. (bnc#844550)

  * Do not restart the signal handler after a trap is reset. (bnc#820149)

  * Work around a crash in libreadline. (bnc#819783)

  * Make skeleton files configurations files. (bnc#776694)" );
	script_tag( name: "affected", value: "bash on SUSE Linux Enterprise Server 11 SP1 LTSS" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:1212-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP1" );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "bash", rpm: "bash~3.2~147.14.20.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bash-doc", rpm: "bash-doc~3.2~147.14.20.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libreadline5", rpm: "libreadline5~5.2~147.14.20.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "readline-doc", rpm: "readline-doc~5.2~147.14.20.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libreadline5-32bit", rpm: "libreadline5-32bit~5.2~147.14.20.1", rls: "SLES11.0SP1" ) )){
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

