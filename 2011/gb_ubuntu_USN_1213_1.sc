if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1213-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840754" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-30 16:02:57 +0200 (Fri, 30 Sep 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1213-1" );
	script_cve_id( "CVE-2011-2995", "CVE-2011-2996", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-2372" );
	script_name( "Ubuntu Update for thunderbird USN-1213-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1213-1" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Benjamin Smedberg, Bob Clary, Jesse Ruderman, and Josh Aas discovered
  multiple memory vulnerabilities in the Gecko rendering engine. An
  attacker could use these to possibly execute arbitrary code with the
  privileges of the user invoking Thunderbird. (CVE-2011-2995, CVE-2011-2996)

  Boris Zbarsky discovered that a frame named 'location' could shadow the
  window.location object unless a script in a page grabbed a reference to the
  true object before the frame was created. This is in violation of the Same
  Origin Policy. A malicious E-Mail could possibly use this to access the
  local file system. (CVE-2011-2999)

  Mark Kaplan discovered an integer underflow in the SpiderMonkey JavaScript
  engine. An attacker could potentially use this to crash Thunderbird.

  Ian Graham discovered that when multiple Location headers were present,
  Thunderbird would use the second one resulting in a possible CRLF injection
  attack. CRLF injection issues can result in a wide variety of attacks, such
  as XSS (Cross-Site Scripting) vulnerabilities, browser cache poisoning, and
  cookie theft. (CVE-2011-3000)

  Mariusz Mlynski discovered that if the user could be convinced to hold down
  the enter key, a malicious website or E-Mail could potential pop up a
  download dialog and the default open action would be selected. This would
  result in potentially malicious content being run with privileges of the
  user invoking Thunderbird. (CVE-2011-2372)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.15+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.15+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.15+build1+nobinonly-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

