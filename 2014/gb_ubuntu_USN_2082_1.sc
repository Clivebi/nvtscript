if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841688" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-20 10:07:55 +0530 (Mon, 20 Jan 2014)" );
	script_cve_id( "CVE-2013-6891" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for cups USN-2082-1" );
	script_tag( name: "affected", value: "cups on Ubuntu 13.10,
  Ubuntu 13.04,
  Ubuntu 12.10" );
	script_tag( name: "insight", value: "Jann Horn discovered that the CUPS lppasswd tool incorrectly
read a user configuration file in certain configurations. A local attacker
could use this to read sensitive information from certain files, bypassing
access restrictions." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2082-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2082-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|13\\.10|13\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "cups-client", ver: "1.6.1-0ubuntu11.5", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "cups-client", ver: "1.7.0~rc1-0ubuntu5.2", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "cups-client", ver: "1.6.2-1ubuntu8", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

