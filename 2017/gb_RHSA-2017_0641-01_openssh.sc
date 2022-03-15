if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871779" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-22 05:48:14 +0100 (Wed, 22 Mar 2017)" );
	script_cve_id( "CVE-2015-8325" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-30 01:29:00 +0000 (Sat, 30 Jun 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for openssh RHSA-2017:0641-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSH is an SSH protocol implementation
supported by a number of Linux, UNIX, and similar operating systems. It includes
the core files necessary for both the OpenSSH client and server.

Security Fix(es):

  * It was discovered that the OpenSSH sshd daemon fetched PAM environment
settings before running the login program. In configurations with
UseLogin=yes and the pam_env PAM module configured to read user environment
settings, a local user could use this flaw to execute arbitrary code as
root. (CVE-2015-8325)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section." );
	script_tag( name: "affected", value: "openssh on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:0641-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-March/msg00047.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "openssh", rpm: "openssh~5.3p1~122.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-askpass", rpm: "openssh-askpass~5.3p1~122.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-clients", rpm: "openssh-clients~5.3p1~122.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~5.3p1~122.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-server", rpm: "openssh-server~5.3p1~122.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

