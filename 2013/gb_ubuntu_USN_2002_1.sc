if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841606" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-29 16:57:01 +0530 (Tue, 29 Oct 2013)" );
	script_cve_id( "CVE-2013-4222", "CVE-2013-4294" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for keystone USN-2002-1" );
	script_tag( name: "affected", value: "keystone on Ubuntu 13.04,
  Ubuntu 12.10" );
	script_tag( name: "insight", value: "Chmouel Boudjnah discovered that Keystone did not properly invalidate user
tokens when a tenant was disabled which allowed an authenticated user to
retain access via the token. (CVE-2013-4222)

Kieran Spear discovered that Keystone did not properly verify PKI tokens
when performing revocation when using the memcache and KVS backends. An
authenticated attacker could exploit this to bypass intended access
restrictions. (CVE-2013-4294)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2002-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2002-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'keystone'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|13\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "python-keystone", ver: "2012.2.4-0ubuntu3.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "python-keystone", ver: "1:2013.1.3-0ubuntu1.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

