if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1069-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840593" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1069-1" );
	script_cve_id( "CVE-2010-3089", "CVE-2011-0707" );
	script_name( "Ubuntu Update for mailman vulnerabilities USN-1069-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|6\\.06 LTS|10\\.04 LTS|8\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1069-1" );
	script_tag( name: "affected", value: "mailman vulnerabilities on Ubuntu 6.06 LTS,
  Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Mailman did not properly sanitize certain fields,
  resulting in cross-site scripting (XSS) vulnerabilities. With cross-site
  scripting vulnerabilities, if a user were tricked into viewing server
  output during a crafted server request, a remote attacker could exploit
  this to modify the contents, or steal confidential data, within the same
  domain." );
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
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "mailman", ver: "2.1.12-2ubuntu0.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU6.06 LTS"){
	if(( res = isdpkgvuln( pkg: "mailman", ver: "2.1.5-9ubuntu4.4", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mailman", ver: "2.1.13-1ubuntu0.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mailman", ver: "2.1.9-9ubuntu1.4", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "mailman", ver: "2.1.13-4ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

