if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1157-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840686" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-24 16:46:35 +0200 (Fri, 24 Jun 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1157-2" );
	script_cve_id( "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2373", "CVE-2011-2377", "CVE-2011-2371", "CVE-2011-2366", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2370", "CVE-2011-2369" );
	script_name( "Ubuntu Update for mozvoikko USN-1157-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1157-2" );
	script_tag( name: "affected", value: "mozvoikko on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1157-1 fixed vulnerabilities in Firefox. This update provides updated
  packages for use with Firefox 5.

  Original advisory details:

  Bob Clary, Kevin Brosnan, Gary Kwong, Jesse Ruderman, Christian Biesinger,
  Bas Schouten, Igor Bukanov, Bill McCloskey, Olli Pettay, Daniel Veditz and
  Marcia Knous discovered multiple memory vulnerabilities in the browser
  rendering engine. An attacker could possibly execute arbitrary code with
  the privileges of the user invoking Firefox. (CVE-2011-2374, CVE-2011-2375)

  Martin Barbella discovered that under certain conditions, viewing a XUL
  document while JavaScript was disabled caused deleted memory to be
  accessed. An attacker could potentially use this to crash Firefox or
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2373)

  Jordi Chancel discovered a vulnerability on multipart/x-mixed-replace
  images due to memory corruption. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-2377)

  Chris Rohlf and Yan Ivnitskiy discovered an integer overflow vulnerability
  in JavaScript Arrays. An attacker could potentially use this to execute
  arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2371)

  It was discovered that Firefox's WebGL textures did not honor same-origin
  policy. If a user were tricked into viewing a malicious site, an attacker
  could potentially view image data from a different site. (CVE-2011-2366)

  Christoph Diehl discovered an out-of-bounds read vulnerability in WebGL
  code. An attacker could potentially read data that other processes had
  stored in the GPU. (CVE-2011-2367)

  Christoph Diehl discovered an invalid write vulnerability in WebGL code. An
  attacker could potentially use this to execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2011-2368)

  It was discovered that an unauthorized site could trigger an installation
  dialog for addons and themes. If a user were tricked into viewing a
  malicious site, an attacker could possibly trick the user into installing a
  malicious addon or theme. (CVE-2011-2370)

  Mario Heiderich discovered a vulnerability in displaying decoded
  HTML-encoded entities inside SVG elements. An attacker could utilize this
  to perform cross-site scripting attacks. (CVE-2011-2369)" );
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
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "xul-ext-mozvoikko", ver: "1.9.0~svn20101114r3591-0ubuntu3.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xul-ext-ubufox", ver: "0.9.1-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xul-ext-webfav", ver: "1.17-0ubuntu5.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

