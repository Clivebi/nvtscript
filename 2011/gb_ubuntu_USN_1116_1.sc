if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1116-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840644" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1116-1" );
	script_cve_id( "CVE-2011-0285" );
	script_name( "Ubuntu Update for krb5 USN-1116-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|9\\.10|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1116-1" );
	script_tag( name: "affected", value: "krb5 on Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 9.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Felipe Ortega discovered that kadmind did not correctly handle password
  changing error conditions. An unauthenticated remote attacker could exploit
  this to crash kadmind, leading to a denial of service." );
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
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.8.1+dfsg-2ubuntu0.9", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.7dfsg~beta3-1ubuntu0.13", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.8.1+dfsg-5ubuntu0.7", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

