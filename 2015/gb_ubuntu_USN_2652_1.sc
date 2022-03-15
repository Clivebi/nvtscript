if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842264" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-01 06:28:55 +0200 (Wed, 01 Jul 2015)" );
	script_cve_id( "CVE-2015-1266", "CVE-2015-1267", "CVE-2015-1268", "CVE-2015-1269" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for oxide-qt USN-2652-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Chromium did not
properly consider the scheme when determining whether a URL is associated with
a WebUI SiteInstance. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to bypass security
restrictions. (CVE-2015-1266)

It was discovered that Blink did not properly restrict the creation
context during creation of a DOM wrapper. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to bypass same-origin restrictions. (CVE-2015-1267, CVE-2015-1268)

It was discovered that Chromium did not properly canonicalize DNS hostnames
before comparing to HSTS or HPKP preload entries. An attacker could
potentially exploit this to bypass intended access restrictions.
(CVE-2015-1269)" );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 14.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2652-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2652-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.7.9-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.7.9-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.7.9-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.7.9-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

