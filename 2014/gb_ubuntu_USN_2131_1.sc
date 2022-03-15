if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841735" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-12 09:30:11 +0530 (Wed, 12 Mar 2014)" );
	script_cve_id( "CVE-2013-6493" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for icedtea-web USN-2131-1" );
	script_tag( name: "affected", value: "icedtea-web on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Michael Scherer discovered that IcedTea Web created temporary
directories in an unsafe fashion. A local attacker could possibly use this
issue to obtain or modify sensitive information from other local user
sessions." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2131-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2131-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|13\\.10|12\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2.3-0ubuntu0.12.04.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-plugin", ver: "1.2.3-0ubuntu0.12.04.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin:i386", ver: "1.4-3ubuntu2.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-plugin:i386", ver: "1.4-3ubuntu2.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.3.2-1ubuntu0.12.10.3", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-plugin", ver: "1.3.2-1ubuntu0.12.10.3", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

