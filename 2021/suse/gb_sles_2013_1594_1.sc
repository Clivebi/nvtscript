if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1594.1" );
	script_cve_id( "CVE-2013-1775", "CVE-2013-1776", "CVE-2013-2776", "CVE-2013-2777" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 19:08:00 +0000 (Mon, 28 Nov 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1594-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1594-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131594-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2013:1594-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This LTSS rollup update fixes the following security issues which allowed to bypass the sudo authentication:

 *

 CVE-2013-1775: sudo allowed local users or physically-proximate attackers to bypass intended time restrictions and retain privileges without re-authenticating by setting the system clock and sudo user timestamp to the epoch.

 *

 CVE-2013-1776: sudo, when the tty_tickets option is enabled, did not properly validate the controlling terminal device, which allowed local users with sudo permissions to hijack the authorization of another terminal via vectors related to connecting to a standard input, output, and error file descriptors of another terminal.

 *

 CVE-2013-2776: sudo, when running on systems without
/proc or the sysctl function with the tty_tickets option enabled, did not properly validate the controlling terminal device, which allowed local users with sudo permissions to hijack the authorization of another terminal via vectors related to connecting to a standard input, output, and error file descriptors of another terminal.

 *

 CVE-2013-2777: sudo, when the tty_tickets option is enabled, did not properly validate the controlling terminal device, which allowed local users with sudo permissions to hijack the authorization of another terminal via vectors related to a session without a controlling terminal device and connecting to a standard input, output, and error file descriptors of another terminal.

Also a non-security bug was fixed:

 * set global ldap option before ldap init (bnc#760697)

Security Issue references:

 * CVE-2013-1775
>
 * CVE-2013-1776
>
 * CVE-2013-2776
>
 * CVE-2013-2777
>" );
	script_tag( name: "affected", value: "'sudo' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.7.6p2~0.2.12.5", rls: "SLES11.0SP1" ) )){
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

