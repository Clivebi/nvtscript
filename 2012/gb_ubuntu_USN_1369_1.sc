if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1369-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840935" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-03-16 10:50:21 +0530 (Fri, 16 Mar 2012)" );
	script_cve_id( "CVE-2012-0449", "CVE-2012-0444", "CVE-2012-0447", "CVE-2012-0446", "CVE-2011-3659", "CVE-2012-0445", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0452", "CVE-2011-3026" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1369-1" );
	script_name( "Ubuntu Update for thunderbird USN-1369-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1369-1" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Nicolas Gregoire and Aki Helin discovered that when processing a malformed
  embedded XSLT stylesheet, Thunderbird can crash due to memory corruption.
  If the user were tricked into opening a specially crafted page, an attacker
  could exploit this to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking
  Thunderbird. (CVE-2012-0449)

  It was discovered that memory corruption could occur during the decoding of
  Ogg Vorbis files. If the user were tricked into opening a specially crafted
  file, an attacker could exploit this to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Thunderbird. (CVE-2012-0444)

  Tim Abraldes discovered that when encoding certain image types the
  resulting data was always a fixed size. There is the possibility of
  sensitive data from uninitialized memory being appended to these images.
  (CVE-2012-0447)

  It was discovered that Thunderbird did not properly perform XPConnect
  security checks. An attacker could exploit this to conduct cross-site
  scripting (XSS) attacks through web pages and Thunderbird extensions. With
  cross-site scripting vulnerabilities, if a user were tricked into viewing a
  specially crafted page, a remote attacker could exploit this to modify the
  contents, or steal confidential data, within the same domain.
  (CVE-2012-0446)

  It was discovered that Thunderbird did not properly handle node removal in
  the DOM. If the user were tricked into opening a specially crafted page, an
  attacker could exploit this to cause a denial of service via application
  crash, or potentially execute code with the privileges of the user invoking
  Thunderbird. (CVE-2011-3659)

  Alex Dvorov discovered that Thunderbird did not properly handle sub-frames
  in form submissions. An attacker could exploit this to conduct phishing
  attacks using HTML5 frames. (CVE-2012-0445)

  Ben Hawkes, Christian Holler, Honza Bombas, Jason Orendorff, Jesse
  Ruderman, Jan Odvarko, Peter Van Der Beken, Bob Clary, and Bill McCloskey
  discovered memory safety issues affecting Thunderbird. If the user were
  tricked into opening a specially crafted page, an attacker could exploit
  these to cause a denial of service via application crash, or potentially
  execute code with the privileges of the user invoking Thunderbird.
  (CVE-2012-0442, CVE-2012-0443)

  Andrew McCreight and Olli Pettay discovered a use-after-free vulnerability
  in the XBL bindings. An attacker could exploit this to cause a denial of
  service vi ...

  Description truncated, please see the referenced URL(s) for more information." );
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
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "10.0.2+build1-0ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

