if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842223" );
	script_version( "2019-11-27T15:23:21+0000" );
	script_tag( name: "last_modification", value: "2019-11-27 15:23:21 +0000 (Wed, 27 Nov 2019)" );
	script_tag( name: "creation_date", value: "2015-06-09 11:08:34 +0200 (Tue, 09 Jun 2015)" );
	script_cve_id( "CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for postgresql-9.4 USN-2621-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-9.4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Benkocs Norbert Attila discovered that
PostgreSQL incorrectly handled authentication timeouts. A remote attacker could
use this flaw to cause the unauthenticated session to crash, possibly leading
to a security issue. (CVE-2015-3165)

Noah Misch discovered that PostgreSQL incorrectly handled certain standard
library function return values, possibly leading to security issues.
(CVE-2015-3166)

Noah Misch discovered that the pgcrypto function could return different
error messages when decrypting using an incorrect key, possibly leading to
a security issue. (CVE-2015-3167)" );
	script_tag( name: "affected", value: "postgresql-9.4 on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2621-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2621-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.2-0ubuntu0.14.10", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.3", ver: "9.3.7-0ubuntu0.14.04", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.1", ver: "9.1.16-0ubuntu0.12.04", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

