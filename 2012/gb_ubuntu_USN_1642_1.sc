if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1642-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841235" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-04 09:48:39 +0530 (Tue, 04 Dec 2012)" );
	script_cve_id( "CVE-2010-2810", "CVE-2012-5821" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1642-1" );
	script_name( "Ubuntu Update for lynx-cur USN-1642-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1642-1" );
	script_tag( name: "affected", value: "lynx-cur on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dan Rosenberg discovered a heap-based buffer overflow in Lynx. If a user
  were tricked into opening a specially crafted page, a remote attacker could
  cause a denial of service via application crash, or possibly execute
  arbitrary code as the user invoking the program. This issue only affected
  Ubuntu 10.04 LTS. (CVE-2010-2810)

  It was discovered that Lynx did not properly verify that an HTTPS
  certificate was signed by a trusted certificate authority. This could allow
  an attacker to perform a 'man in the middle' (MITM) attack which would make
  the user believe their connection is secure, but is actually being
  monitored. This update changes the behavior of Lynx such that self-signed
  certificates no longer validate. Users requiring the previous behavior can
  use the 'FORCE_SSL_PROMPT' option in lynx.cfg. (CVE-2012-5821)" );
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
	if(( res = isdpkgvuln( pkg: "lynx-cur", ver: "2.8.8dev.9-2ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "lynx-cur", ver: "2.8.8dev.9-2ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "lynx-cur", ver: "2.8.8dev.2-1ubuntu0.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "lynx-cur", ver: "2.8.8dev.12-2ubuntu0.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

