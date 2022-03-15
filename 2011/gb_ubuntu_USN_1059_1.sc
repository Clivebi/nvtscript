if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1059-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840583" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "USN", value: "1059-1" );
	script_cve_id( "CVE-2010-3304", "CVE-2010-3706", "CVE-2010-3707", "CVE-2010-3779", "CVE-2010-3780" );
	script_name( "Ubuntu Update for dovecot vulnerabilities USN-1059-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1059-1" );
	script_tag( name: "affected", value: "dovecot vulnerabilities on Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the ACL plugin in Dovecot would incorrectly
  propagate ACLs to new mailboxes. A remote authenticated user could possibly
  read new mailboxes that were created with the wrong ACL. (CVE-2010-3304)

  It was discovered that the ACL plugin in Dovecot would incorrectly merge
  ACLs in certain circumstances. A remote authenticated user could possibly
  bypass intended access restrictions and gain access to mailboxes.
  (CVE-2010-3706, CVE-2010-3707)

  It was discovered that the ACL plugin in Dovecot would incorrectly grant
  the admin permission to owners of certain mailboxes. A remote authenticated
  user could possibly bypass intended access restrictions and gain access to
  mailboxes. (CVE-2010-3779)

  It was discovered that Dovecot incorrectly handled the simultaneous
  disconnect of a large number of sessions. A remote authenticated user could
  use this flaw to cause Dovecot to crash, resulting in a denial of service.
  (CVE-2010-3780)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "dovecot-common", ver: "1.2.12-1ubuntu8.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-dbg", ver: "1.2.12-1ubuntu8.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-dev", ver: "1.2.12-1ubuntu8.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-imapd", ver: "1.2.12-1ubuntu8.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-pop3d", ver: "1.2.12-1ubuntu8.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-postfix", ver: "1.2.12-1ubuntu8.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mail-stack-delivery", ver: "1.2.12-1ubuntu8.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "dovecot-common", ver: "1.2.9-1ubuntu6.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-dbg", ver: "1.2.9-1ubuntu6.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-dev", ver: "1.2.9-1ubuntu6.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-imapd", ver: "1.2.9-1ubuntu6.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-pop3d", ver: "1.2.9-1ubuntu6.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dovecot-postfix", ver: "1.2.9-1ubuntu6.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

