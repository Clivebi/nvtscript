if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842771" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-19 05:21:28 +0200 (Thu, 19 May 2016)" );
	script_cve_id( "CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1663", "CVE-2016-1665", "CVE-2016-1666", "CVE-2016-1667", "CVE-2016-1668", "CVE-2016-1669", "CVE-2016-1670" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for oxide-qt USN-2960-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An out of bounds write was discovered in
  Blink. If a user were tricked in to opening a specially crafted website, an
  attacker could potentially exploit this to cause a denial of service via
  renderer crash, or execute arbitrary code. (CVE-2016-1660)

  It was discovered that Blink assumes that a frame which passes same-origin
  checks is local in some cases. If a user were tricked in to opening a
  specially crafted website, an attacker could potentially exploit this to
  cause a denial of service via renderer crash, or execute arbitrary code.
  (CVE-2016-1661)

  A use-after-free was discovered in the V8 bindings in Blink. If a user
  were tricked in to opening a specially crafted website, an attacker could
  potentially exploit this to cause a denial of service via renderer crash,
  or execute arbitrary code. (CVE-2016-1663)

  It was discovered that the JSGenericLowering class in V8 mishandles
  comparison operators. If a user were tricked in to opening a specially
  crafted website, an attacker could potentially exploit this to obtain
  sensitive information. (CVE-2016-1665)

  Multiple security issues were discovered in Chromium. If a user were
  tricked in to opening a specially crafted website, an attacker could
  potentially exploit these to read uninitialized memory, cause a denial
  of service via application crash or execute arbitrary code.
  (CVE-2016-1666)

  It was discovered that the TreeScope::adoptIfNeeded function in Blink
  does not prevent script execution during node-adoption operations. If a
  user were tricked in to opening a specially crafted website, an attacker
  could potentially exploit this to bypass same origin restrictions.
  (CVE-2016-1667)

  It was discovered that the forEachForBinding in the V8 bindings in Blink
  uses an improper creation context. If a user were tricked in to opening a
  specially crafted website, an attacker could potentially exploit this to
  bypass same origin restrictions. (CVE-2016-1668)

  A buffer overflow was discovered in V8. If a user were tricked in to
  opening a specially crafted website, an attacker could potentially exploit
  this to cause a denial of service via renderer crash, or execute arbitrary
  code. (CVE-2016-1669)

  A race condition was discovered in ResourceDispatcherHostImpl in Chromium.
  An attacker could potentially exploit this to make arbitrary HTTP
  requests. (CVE-2016-1670)" );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2960-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2960-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.14.9-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.14.9-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.14.9-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.14.9-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.14.9-0ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.14.9-0ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

