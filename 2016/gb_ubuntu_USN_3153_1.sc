if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842990" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-10 06:13:45 +0100 (Sat, 10 Dec 2016)" );
	script_cve_id( "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5212", "CVE-2016-5215", "CVE-2016-5222", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226", "CVE-2016-9650", "CVE-2016-9652", "CVE-2016-5213", "CVE-2016-5219", "CVE-2016-9651", "CVE-2016-5221" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for oxide-qt USN-3153-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered
  in Chromium. If a user were tricked in to opening a specially crafted website,
  an attacker could potentially exploit these to conduct cross-site scripting
  (XSS) attacks, read uninitialized memory, obtain sensitive information, spoof
  the webview URL, bypass same origin restrictions, cause a denial of service
via application crash, or execute arbitrary code. (CVE-2016-5204,
CVE-2016-5205, CVE-2016-5207, CVE-2016-5208, CVE-2016-5209, CVE-2016-5212,
CVE-2016-5215, CVE-2016-5222, CVE-2016-5224, CVE-2016-5225, CVE-2016-5226,
CVE-2016-9650, CVE-2016-9652)

Multiple vulnerabilities were discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit these to obtain sensitive information, cause a denial of service
via application crash, or execute arbitrary code. (CVE-2016-5213,
CVE-2016-5219, CVE-2016-9651)

An integer overflow was discovered in ANGLE. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code. (CVE-2016-5221)" );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3153-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3153-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.19.4-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.19.4-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.19.4-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.19.4-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.19.4-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.19.4-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

