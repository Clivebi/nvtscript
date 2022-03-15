if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842138" );
	script_version( "2020-02-04T09:04:16+0000" );
	script_tag( name: "last_modification", value: "2020-02-04 09:04:16 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-03-24 07:10:29 +0100 (Tue, 24 Mar 2015)" );
	script_cve_id( "CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for gnutls28 USN-2540-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls28'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GnuTLS did not
perform date and time checks on CA certificates, contrary to expectations.
This issue only affected Ubuntu 10.04 LTS. (CVE-2014-8155)

Nikos Mavrogiannopoulos discovered that GnuTLS incorrectly verified that
signature algorithms matched. A remote attacker could possibly use this
issue to downgrade to a disallowed algorithm. This issue only affected
Ubuntu 10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-0282)

It was discovered that GnuTLS incorrectly verified certificate algorithms.
A remote attacker could possibly use this issue to downgrade to a
disallowed algorithm. (CVE-2015-0294)" );
	script_tag( name: "affected", value: "gnutls28 on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2540-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2540-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS|10\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libgnutls-deb0-28:amd64", ver: "3.2.16-1ubuntu2.2", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgnutls-deb0-28:i386", ver: "3.2.16-1ubuntu2.2", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgnutls26:amd64", ver: "2.12.23-12ubuntu2.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgnutls26:i386", ver: "2.12.23-12ubuntu2.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgnutls26", ver: "2.12.14-5ubuntu3.9", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgnutls26", ver: "2.8.5-2ubuntu0.7", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

