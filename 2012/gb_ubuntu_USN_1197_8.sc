if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1197-8/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840971" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-02 10:35:00 +0530 (Mon, 02 Apr 2012)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1197-8" );
	script_name( "Ubuntu Update for ca-certificates-java USN-1197-8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1197-8" );
	script_tag( name: "affected", value: "ca-certificates-java on Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1197-7 fixed a vulnerability in ca-certificates-java. The new package
  broke upgrades from Ubuntu 11.04 to Ubuntu 11.10. This update fixes the
  problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that Dutch Certificate Authority DigiNotar had
  mis-issued multiple fraudulent certificates. These certificates could allow
  an attacker to perform a 'man in the middle' (MITM) attack which would make
  the user believe their connection is secure, but is actually being
  monitored." );
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
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "ca-certificates-java", ver: "20110912ubuntu3.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

