if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1251-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840801" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-11 09:55:39 +0530 (Fri, 11 Nov 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1251-1" );
	script_cve_id( "CVE-2011-3004", "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650" );
	script_name( "Ubuntu Update for firefox USN-1251-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1251-1" );
	script_tag( name: "affected", value: "firefox on Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that CVE-2011-3004, which addressed possible privilege
  escalation in addons, also affected Firefox 3.6. An attacker could
  potentially exploit Firefox when an add-on was installed that used
  loadSubscript in vulnerable ways. (CVE-2011-3647)

  Yosuke Hasegawa discovered that the Mozilla browser engine mishandled
  invalid sequences in the Shift-JIS encoding. A malicious website could
  possibly use this flaw this to steal data or inject malicious scripts into
  web content. (CVE-2011-3648)

  Marc Schoenefeld discovered that using Firebug to profile a JavaScript file
  with many functions would cause Firefox to crash. An attacker might be able
  to exploit this without using the debugging APIs which would potentially
  allow an attacker to remotely crash the browser. (CVE-2011-3650)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.24+build2+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.24+build2+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.24+build2+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.24+build2+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

