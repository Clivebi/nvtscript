if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842973" );
	script_version( "2019-11-19T07:59:35+0000" );
	script_tag( name: "last_modification", value: "2019-11-19 07:59:35 +0000 (Tue, 19 Nov 2019)" );
	script_tag( name: "creation_date", value: "2016-12-02 05:33:49 +0100 (Fri, 02 Dec 2016)" );
	script_cve_id( "CVE-2016-5198", "CVE-2016-5200", "CVE-2016-5202", "CVE-2016-5199" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for oxide-qt USN-3133-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security vulnerabilities were
  discovered in Chromium. If a user were tricked in to opening a specially
  crafted website, an attacker could potentially exploit these to obtain sensitive
  information, cause a denial of service via application crash, or execute
  arbitrary code. (CVE-2016-5198, CVE-2016-5200, CVE-2016-5202)

A heap-corruption issue was discovered in FFmpeg. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2016-5199)" );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 16.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3133-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3133-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS|16\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.18.5-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.18.5-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.18.5-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.18.5-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.18.5-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.18.5-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

