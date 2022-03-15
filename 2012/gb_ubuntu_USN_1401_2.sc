if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1401-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840961" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-26 14:18:07 +0530 (Mon, 26 Mar 2012)" );
	script_cve_id( "CVE-2011-3658", "CVE-2012-0457", "CVE-2012-0456", "CVE-2012-0455", "CVE-2012-0458", "CVE-2012-0461", "CVE-2012-0464" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1401-2" );
	script_name( "Ubuntu Update for thunderbird USN-1401-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1401-2" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1401-1 fixed vulnerabilities in Xulrunner. This update provides the
  corresponding fixes for Thunderbird.

  Original advisory details:

  It was discovered that a flaw in the Mozilla SVG implementation could
  result in an out-of-bounds memory access if SVG elements were removed
  during a DOMAttrModified event handler. If the user were tricked into
  opening a specially crafted page, an attacker could exploit this to cause a
  denial of service via application crash. (CVE-2011-3658)

  Atte Kettunen discovered a use-after-free vulnerability in the Gecko
  Rendering Engine's handling of SVG animations. An attacker could
  potentially exploit this to execute arbitrary code with the privileges of
  the user invoking the Xulrunner based application. (CVE-2012-0457)

  Atte Kettunen discovered an out of bounds read vulnerability in the Gecko
  Rendering Engine's handling of SVG Filters. An attacker could potentially
  exploit this to make data from the user's memory accessible to the page
  content. (CVE-2012-0456)

  Soroush Dalili discovered that the Gecko Rendering Engine did not
  adequately protect against dropping JavaScript links onto a frame. A remote
  attacker could, through cross-site scripting (XSS), exploit this to modify
  the contents of the frame or steal confidential data. (CVE-2012-0455)

  Mariusz Mlynski discovered that the Home button accepted JavaScript links
  to set the browser Home page. An attacker could use this vulnerability to
  get the script URL loaded in the privileged about:sessionrestore context.
  (CVE-2012-0458)

  Bob Clary, Vincenzo Iozzo, and Willem Pinckaers discovered memory safety
  issues affecting Firefox. If the user were tricked into opening a specially
  crafted page, an attacker could exploit these to cause a denial of service
  via application crash, or potentially execute code with the privileges of
  the user invoking Firefox. (CVE-2012-0461, CVE-2012-0464)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.20+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.20+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.20+build1+nobinonly-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

