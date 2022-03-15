if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843235" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-14 15:55:04 +0530 (Fri, 14 Jul 2017)" );
	script_cve_id( "CVE-2017-7526", "CVE-2017-9526" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libgcrypt20 USN-3347-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgcrypt20'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Daniel J. Bernstein, Joachim Breitner,
  Daniel Genkin, Leon Groot Bruinderink, Nadia Heninger, Tanja Lange, Christine
  van Vredendaal, and Yuval Yarom discovered that Libgcrypt was susceptible to an
  attack via side channels. A local attacker could use this attack to recover RSA
  private keys. (CVE-2017-7526) It was discovered that Libgcrypt was susceptible
  to an attack via side channels. A local attacker could use this attack to
  possibly recover EdDSA private keys. This issue only applied to Ubuntu 16.04
  LTS, Ubuntu 16.10 and Ubuntu 17.04. (CVE-2017-9526)" );
	script_tag( name: "affected", value: "libgcrypt20 on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3347-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3347-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libgcrypt11:i386", ver: "1.5.3-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgcrypt11:amd64", ver: "1.5.3-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "libgcrypt20:i386", ver: "1.7.6-1ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgcrypt20:amd64", ver: "1.7.6-1ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "libgcrypt20:i386", ver: "1.7.2-2ubuntu1.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgcrypt20:amd64", ver: "1.7.2-2ubuntu1.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgcrypt20:i386", ver: "1.6.5-2ubuntu0.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgcrypt20:amd64", ver: "1.6.5-2ubuntu0.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

