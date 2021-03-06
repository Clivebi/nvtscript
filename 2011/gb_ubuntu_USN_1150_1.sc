if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1150-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840702" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-07-18 15:23:56 +0200 (Mon, 18 Jul 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1150-1" );
	script_cve_id( "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2374", "CVE-2011-2376", "CVE-2011-2373", "CVE-2011-2377", "CVE-2011-2371", "CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2363", "CVE-2011-2362" );
	script_name( "Ubuntu Update for thunderbird USN-1150-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1150-1" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Multiple memory vulnerabilities were discovered in the browser rendering
  engine. An attacker could use these to possibly execute arbitrary code with
  the privileges of the user invoking Thunderbird. (CVE-2011-2364,
  CVE-2011-2365, CVE-2011-2374, CVE-2011-2376)

  Martin Barbella discovered that under certain conditions, viewing a XUL
  document while JavaScript was disabled caused deleted memory to be
  accessed. An attacker could potentially use this to crash Thunderbird or
  execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2011-2373)

  Jordi Chancel discovered a vulnerability on multipart/x-mixed-replace
  images due to memory corruption. An attacker could potentially use this to
  crash Thunderbird or execute arbitrary code with the privileges of the user
  invoking Thunderbird. (CVE-2011-2377)

  Chris Rohlf and Yan Ivnitskiy discovered an integer overflow vulnerability
  in JavaScript Arrays. An attacker could potentially use this to execute
  arbitrary code with the privileges of the user invoking Thunderbird.
  (CVE-2011-2371)

  Multiple use-after-free vulnerabilities were discovered. An attacker could
  potentially use these to execute arbitrary code with the privileges of the
  user invoking Thunderbird. (CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

  David Chan discovered that cookies did not honor same-origin conventions.
  This could potentially lead to cookie data being leaked to a third party.
  (CVE-2011-2362)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.11+build2+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.11+build2+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.11+build2+nobinonly-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

