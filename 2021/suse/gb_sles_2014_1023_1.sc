if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1023.1" );
	script_cve_id( "CVE-2012-5519", "CVE-2014-3537", "CVE-2014-5029", "CVE-2014-5030", "CVE-2014-5031" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:32:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1023-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1023-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141023-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'CUPS' package(s) announced via the SUSE-SU-2014:1023-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes various issues in CUPS.

 *

 CVE-2014-3537 CVE-2014-5029 CVE-2014-5030 CVE-2014-5031: Various insufficient symbolic link checking could lead to privilege escalation from the lp user to root.

 *

 Similar to that, this update hardens various permissions of CUPS,
which could have been used by users allowed to administrate the CUPS Server to escalate privileges to 'root'.

 *

 CVE-2012-5519: The patch adds better default protection against misuse of privileges by normal users who have been specifically allowed by root to do cupsd configuration changes

 The new ConfigurationChangeRestriction cupsd.conf directive specifies the level of restriction for cupsd.conf changes that happen via HTTP/IPP requests to the running cupsd (e.g. via CUPS web interface
 or via the cupsctl command).

 By default certain cupsd.conf directives that deal with filenames,
paths, and users can no longer be changed via requests to the running cupsd but only by manual editing the cupsd.conf file and its default file permissions permit only root to write the cupsd.conf file.

 Those directives are: ConfigurationChangeRestriction, AccessLog,
BrowseLDAPCACertFile, CacheDir, ConfigFilePerm, DataDir, DocumentRoot,
ErrorLog, FileDevice, FontPath, Group, LogFilePerm, PageLog, Printcap,
PrintcapFormat, PrintcapGUI, RemoteRoot, RequestRoot, ServerBin,
ServerCertificate, ServerKey, ServerRoot, StateDir, SystemGroup,
SystemGroupAuthKey, TempDir, User.

 The default group of users who are allowed to do cupsd configuration changes via requests to the running cupsd (i.e. the SystemGroup directive in cupsd.conf) is set to 'root' only.

Additional bugfixes:

 *

 A trailing '@REALM' is stripped from the username for Kerberos authentication (CUPS STR#3972 bnc#827109).

 *

 The hardcoded printing delay of 5 seconds for the 'socket' backend conditional only on Mac OS X which is the only platform that needs it
(CUPS STR#3495 bnc#802408).

Security Issues:

 * CVE-2014-3537
 * CVE-2012-5519" );
	script_tag( name: "affected", value: "'CUPS' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "cups", rpm: "cups~1.3.9~8.46.52.2", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-client", rpm: "cups-client~1.3.9~8.46.52.2", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-libs", rpm: "cups-libs~1.3.9~8.46.52.2", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-libs-32bit", rpm: "cups-libs-32bit~1.3.9~8.46.52.2", rls: "SLES11.0SP1" ) )){
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

