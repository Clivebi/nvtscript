if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1070-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840590" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1070-1" );
	script_cve_id( "CVE-2011-0414" );
	script_name( "Ubuntu Update for bind9 vulnerability USN-1070-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1070-1" );
	script_tag( name: "affected", value: "bind9 vulnerability on Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Bind incorrectly handled IXFR transfers and dynamic
  updates while under heavy load when used as an authoritative server. A
  remote attacker could use this flaw to cause Bind to stop responding,
  resulting in a denial of service." );
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
	if(( res = isdpkgvuln( pkg: "bind9-host", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "bind9", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "bind9utils", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsutils", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libbind9-60", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdns66", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libisc60", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libisccc60", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libisccfg60", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liblwres60", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "lwresd", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "host", ver: "9.7.1.dfsg.P2-2ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

