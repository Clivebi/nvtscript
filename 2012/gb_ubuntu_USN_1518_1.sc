if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1518-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841094" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 11:18:51 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-3817" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1518-1" );
	script_name( "Ubuntu Update for bind9 USN-1518-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1518-1" );
	script_tag( name: "affected", value: "bind9 on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Einar Lonn discovered that Bind incorrectly initialized the failing-query
  cache. A remote attacker could use this flaw to cause Bind to crash,
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libdns64", ver: "9.7.0.dfsg.P1-1ubuntu0.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libdns81", ver: "9.8.1.dfsg.P1-4ubuntu0.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "libdns69", ver: "9.7.3.dfsg-1ubuntu4.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libdns69", ver: "9.7.3.dfsg-1ubuntu2.5", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

