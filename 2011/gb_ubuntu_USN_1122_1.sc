if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1122-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840652" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1122-1" );
	script_cve_id( "CVE-2011-0081", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0080", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0072", "CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0073", "CVE-2011-0067", "CVE-2011-0071", "CVE-2011-1202" );
	script_name( "Ubuntu Update for thunderbird USN-1122-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1122-1" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that there was a vulnerability in the memory handling of
  certain types of content. An attacker could exploit this to possibly run
  arbitrary code as the user running Thunderbird. (CVE-2011-0081)

  It was discovered that Thunderbird incorrectly handled certain JavaScript
  requests. If JavaScript were enabled, an attacker could exploit this to
  possibly run arbitrary code as the user running Thunderbird.
  (CVE-2011-0069)

  Ian Beer discovered a vulnerability in the memory handling of a certain
  types of documents. An attacker could exploit this to possibly run
  arbitrary code as the user running Thunderbird. (CVE-2011-0070)

  Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren and Jesse Ruderman
  discovered several memory vulnerabilities. An attacker could exploit these
  to possibly run arbitrary code as the user running Thunderbird.
  (CVE-2011-0080)

  Aki Helin discovered multiple vulnerabilities in the HTML rendering code.
  An attacker could exploit these to possibly run arbitrary code as the user
  running Thunderbird. (CVE-2011-0074, CVE-2011-0075)

  Ian Beer discovered multiple overflow vulnerabilities. An attacker could
  exploit these to possibly run arbitrary code as the user running
  Thunderbird. (CVE-2011-0077, CVE-2011-0078)

  Martin Barbella discovered a memory vulnerability in the handling of
  certain DOM elements. An attacker could exploit this to possibly run
  arbitrary code as the user running Thunderbird. (CVE-2011-0072)

  It was discovered that there were use-after-free vulnerabilities in
  Thunderbird's mChannel and mObserverList objects. An attacker could exploit
  these to possibly run arbitrary code as the user running Thunderbird.
  (CVE-2011-0065, CVE-2011-0066)

  It was discovered that there was a vulnerability in the handling of the
  nsTreeSelection element. An attacker sending a specially crafted E-Mail
  could exploit this to possibly run arbitrary code as the user running
  Thunderbird. (CVE-2011-0073)

  Paul Stone discovered a vulnerability in the handling of Java applets. If
  plugins were enabled, an attacker could use this to mimic interaction with
  form autocomplete controls and steal entries from the form history.
  (CVE-2011-0067)

  Soroush Dalili discovered a vulnerability in the resource: protocol. This
  could potentially allow an attacker to load arbitrary files that were
  accessible to the user running Thunderbird. (CVE-2011-0071)

  Chris Evans discovered a vulnerability in Thunderbird's XSLT generate-id()
  function. An attacker could possibly use this vulnerability to make other
  attacks more reliable. (CVE-2011-1202)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.10+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.10+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
