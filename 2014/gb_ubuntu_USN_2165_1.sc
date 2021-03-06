if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841774" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-08 12:07:01 +0530 (Tue, 08 Apr 2014)" );
	script_cve_id( "CVE-2014-0160", "CVE-2014-0076" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for openssl USN-2165-1" );
	script_tag( name: "affected", value: "openssl on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Neel Mehta discovered that OpenSSL incorrectly handled memory
in the TLS heartbeat extension. An attacker could use this issue to obtain up
to 64k of memory contents from the client or server, possibly leading to the
disclosure of private keys and other sensitive information. (CVE-2014-0160)

Yuval Yarom and Naomi Benger discovered that OpenSSL incorrectly handled
timing during swap operations in the Montgomery ladder implementation. An
attacker could use this issue to perform side-channel attacks and possibly
recover ECDSA nonces. (CVE-2014-0076)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2165-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2165-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|13\\.10|12\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1-4ubuntu5.12", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1e-3ubuntu1.2", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1c-3ubuntu2.7", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

