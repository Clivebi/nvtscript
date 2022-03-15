if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1335-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840866" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-01-20 11:00:04 +0530 (Fri, 20 Jan 2012)" );
	script_cve_id( "CVE-2010-2642", "CVE-2011-0433", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1335-1" );
	script_name( "Ubuntu Update for t1lib USN-1335-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1335-1" );
	script_tag( name: "affected", value: "t1lib on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Jon Larimer discovered that t1lib did not properly parse AFM fonts. If a
  user were tricked into using a specially crafted font file, a remote
  attacker could cause t1lib to crash or possibly execute arbitrary code with
  user privileges. (CVE-2010-2642, CVE-2011-0433)

  Jonathan Brossard discovered that t1lib did not correctly handle certain
  malformed font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause t1lib to crash. (CVE-2011-1552,
  CVE-2011-1553, CVE-2011-1554)" );
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
	if(( res = isdpkgvuln( pkg: "libt1-5", ver: "5.1.2-3ubuntu0.10.10.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libt1-5", ver: "5.1.2-3ubuntu0.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libt1-5", ver: "5.1.2-3ubuntu0.11.04.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

