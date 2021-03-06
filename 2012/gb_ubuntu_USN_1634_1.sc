if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1634-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841218" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-23 11:50:53 +0530 (Fri, 23 Nov 2012)" );
	script_cve_id( "CVE-2012-4571" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "USN", value: "1634-1" );
	script_name( "Ubuntu Update for python-keyring USN-1634-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|12\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1634-1" );
	script_tag( name: "affected", value: "python-keyring on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dwayne Litzenberger discovered that Python Keyring's CryptedFileKeyring
  file format used weak cryptography. A local attacker may use this issue to
  brute-force CryptedFileKeyring keyring files. This issue only affected
  Ubuntu 11.10 and Ubuntu 12.04 LTS. (CVE-2012-4571)

  It was discovered that Python Keyring created keyring files with insecure
  permissions. A local attacker could use this issue to access keyring files
  belonging to other users." );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-keyring", ver: "0.9.2-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-keyring", ver: "0.9.2-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "python-keyring", ver: "0.9.2-0ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "python-keyring", ver: "0.9.2-1ubuntu0.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-keyring", ver: "0.9.2-1ubuntu0.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

