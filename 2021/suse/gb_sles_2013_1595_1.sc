if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1595.1" );
	script_cve_id( "CVE-2013-1775", "CVE-2013-1776", "CVE-2013-2776", "CVE-2013-2777" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 19:08:00 +0000 (Mon, 28 Nov 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1595-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1595-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131595-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2013:1595-1 advisory." );
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

 * escape string passed to ldap search (bnc#724490)

Security Issue references:

 * CVE-2013-1775
>
 * CVE-2013-1776
>
 * CVE-2013-2776
>
 * CVE-2013-2777
>" );
	script_tag( name: "affected", value: "'sudo' package(s) on SUSE Linux Enterprise Server 10 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.6.8p12~18.21.8", rls: "SLES10.0SP3" ) )){
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

