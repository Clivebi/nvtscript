if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843853" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2018-12405", "CVE-2018-12406", "CVE-2018-12407", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18498", "CVE-2018-18495", "CVE-2018-18497" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 12:55:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-12-12 07:47:50 +0100 (Wed, 12 Dec 2018)" );
	script_name( "Ubuntu Update for firefox USN-3844-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3844-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3844-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the USN-3844-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, bypass same-origin
restritions, or execute arbitrary code. (CVE-2018-12405, CVE-2018-12406,
CVE-2018-12407, CVE-2018-17466, CVE-2018-18492, CVE-2018-18493,
CVE-2018-18494, CVE-2018-18498)

Multiple security issues were discovered in WebExtensions. If a user were
tricked in to installing a specially crafted extension, an attacker could
potentially exploit these to open privileged pages, or bypass other
security restrictions. (CVE-2018-18495, CVE-2018-18497)" );
	script_tag( name: "affected", value: "firefox on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "64.0+build3-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "64.0+build3-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "64.0+build3-0ubuntu0.18.10.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "64.0+build3-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

