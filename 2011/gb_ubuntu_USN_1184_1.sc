if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1184-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840727" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-24 09:14:07 +0200 (Wed, 24 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1184-1" );
	script_cve_id( "CVE-2011-2982", "CVE-2011-2981", "CVE-2011-0084", "CVE-2011-2984", "CVE-2011-2378", "CVE-2011-2983" );
	script_name( "Ubuntu Update for firefox USN-1184-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1184-1" );
	script_tag( name: "affected", value: "firefox on Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Gary Kwong, Igor Bukanov, and Bob Clary discovered multiple memory
  vulnerabilities in the browser rendering engine. An attacker could use
  these to possibly execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-2982)

  It was discovered that a vulnerability in event management code could
  permit JavaScript to be run in the wrong context. This could potentially
  allow a malicious website to run code as another website or with escalated
  privileges within the browser. (CVE-2011-2981)

  It was discovered that an SVG text manipulation routine contained a
  dangling pointer vulnerability. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-0084)

  It was discovered that web content could receive chrome privileges if it
  registered for drop events and a browser tab element was dropped into the
  content area. This could potentially allow a malicious website to run code
  with escalated privileges within the browser. (CVE-2011-2984)

  It was discovered that appendChild contained a dangling pointer
  vulnerability. An attacker could potentially use this to crash Firefox or
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2378)

  It was discovered that data from other domains could be read when
  RegExp.input was set. This could potentially allow a malicious website
  access to private data from other domains. (CVE-2011-2983)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.20+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.20+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.20+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.20+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

