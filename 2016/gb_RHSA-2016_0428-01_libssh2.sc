if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871571" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-03-11 06:01:37 +0100 (Fri, 11 Mar 2016)" );
	script_cve_id( "CVE-2016-0787" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for libssh2 RHSA-2016:0428-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libssh2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libssh2 packages provide a library that implements the SSHv2 protocol.

A type confusion issue was found in the way libssh2 generated ephemeral
secrets for the diffie-hellman-group1 and diffie-hellman-group14 key
exchange methods. This would cause an SSHv2 Diffie-Hellman handshake to use
significantly less secure random parameters. (CVE-2016-0787)

Red Hat would like to thank Aris Adamantiadis for reporting this issue.

All libssh2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing these
updated packages, all running applications using libssh2 must be restarted
for this update to take effect." );
	script_tag( name: "affected", value: "libssh2 on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:0428-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-March/msg00032.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "libssh2", rpm: "libssh2~1.4.3~10.el7_2.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libssh2-debuginfo", rpm: "libssh2-debuginfo~1.4.3~10.el7_2.1", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "libssh2", rpm: "libssh2~1.4.2~2.el6_7.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libssh2-debuginfo", rpm: "libssh2-debuginfo~1.4.2~2.el6_7.1", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

