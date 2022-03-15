if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842884" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-15 05:47:25 +0200 (Thu, 15 Sep 2016)" );
	script_cve_id( "CVE-2016-5141", "CVE-2016-5142", "CVE-2016-5143", "CVE-2016-5144", "CVE-2016-5145", "CVE-2016-5146", "CVE-2016-5167", "CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5150", "CVE-2016-5153", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5161", "CVE-2016-5164", "CVE-2016-5165" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for oxide-qt USN-3058-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in Blink involving
  the provisional URL for an initially empty document. An attacker could potentially
  exploit this to spoof the currently displayed URL. (CVE-2016-5141)

A use-after-free was discovered in the WebCrypto implementation in Blink.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2016-5142)

It was discovered that the devtools subsystem in Blink mishandles various
parameters. An attacker could exploit this to bypass intended access
restrictions. (CVE-2016-5143, CVE-2016-5144)

It was discovered that Blink does not ensure that a taint property is
preserved after a structure-clone operation on an ImageBitmap object
derived from a cross-origin image. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
bypass same origin restrictions. (CVE-2016-5145)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5146, CVE-2016-5167)

It was discovered that Blink mishandles deferred page loads. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2016-5147)

An issue was discovered in Blink related to widget updates. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2016-5148)

A use-after-free was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5150)

A use-after-free was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5153)

It was discovered that Chromium does not correctly validate access to the
initial document. An attacker could potentially exploit this to spoof the
currently displayed URL. (CVE-2016-5155)

A use-after-free was discovered in the event bindings in Blink. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially ex ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3058-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3058-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.17.7-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.17.7-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.17.7-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.17.7-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

