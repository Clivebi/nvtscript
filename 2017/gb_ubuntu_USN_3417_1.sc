if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843305" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-15 07:09:14 +0200 (Fri, 15 Sep 2017)" );
	script_cve_id( "CVE-2017-0379" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-16 19:29:00 +0000 (Wed, 16 Jan 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libgcrypt20 USN-3417-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgcrypt20'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Daniel Genkin, Luke Valenta, and Yuval Yarom
  discovered that Libgcrypt was susceptible to an attack via side channels. A
  local attacker could use this attack to recover Curve25519 private keys." );
	script_tag( name: "affected", value: "libgcrypt20 on Ubuntu 17.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3417-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3417-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU17\\.04" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "libgcrypt20:amd64", ver: "1.7.6-1ubuntu0.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgcrypt20:i386", ver: "1.7.6-1ubuntu0.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

