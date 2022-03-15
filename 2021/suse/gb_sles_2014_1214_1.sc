if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1214.1" );
	script_cve_id( "CVE-2012-3410", "CVE-2014-0475", "CVE-2014-6271" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1214-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1214-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141214-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash' package(s) announced via the SUSE-SU-2014:1214-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "bash has been updated to fix a critical security issue.

In some circumstances, the shell would evaluate shellcode in environment variables passed at startup time. This allowed code execution by local or remote attackers who could pass environment variables to bash scripts.
(CVE-2014-6271)

Additionally, the following bugs have been fixed:

 * Avoid possible buffer overflow when expanding the /dev/fd prefix
 with e.g. the test built-in. (CVE-2012-3410)
 * Enable workaround for changed behavior of sshd. (bnc#688469)

Security Issues:

 * CVE-2014-6271
 * CVE-2012-3410" );
	script_tag( name: "affected", value: "'bash' package(s) on SUSE Linux Enterprise Server 10 SP3." );
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
if(release == "SLES10.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "bash", rpm: "bash~3.1~24.32.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "readline-32bit", rpm: "readline-32bit~5.1~24.32.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "readline", rpm: "readline~5.1~24.32.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "readline-devel-32bit", rpm: "readline-devel-32bit~5.1~24.32.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "readline-devel", rpm: "readline-devel~5.1~24.32.1", rls: "SLES10.0SP3" ) )){
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

