if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1347-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840879" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-01 11:36:55 +0530 (Wed, 01 Feb 2012)" );
	script_cve_id( "CVE-2011-0433" );
	script_xref( name: "USN", value: "1347-1" );
	script_name( "Ubuntu Update for evince USN-1347-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1347-1" );
	script_tag( name: "affected", value: "evince on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Evince did not properly parse AFM font files when
  processing DVI files. If a user were tricked into opening a specially
  crafted DVI file, an attacker could cause Evince to crash or potentially
  execute arbitrary code with the privileges of the user invoking the
  program.

  In the default installation, attackers would be isolated by the Evince
  AppArmor profile." );
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
	if(( res = isdpkgvuln( pkg: "libevdocument3", ver: "2.32.0-0ubuntu1.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libevdocument2", ver: "2.30.3-0ubuntu1.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libevdocument3", ver: "2.32.0-0ubuntu12.4", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
