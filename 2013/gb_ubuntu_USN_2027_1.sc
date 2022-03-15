if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841632" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-11-18 17:12:32 +0530 (Mon, 18 Nov 2013)" );
	script_cve_id( "CVE-2013-4282" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for spice USN-2027-1" );
	script_tag( name: "affected", value: "spice on Ubuntu 13.10,
  Ubuntu 13.04" );
	script_tag( name: "insight", value: "Tomas Jamrisko discovered that SPICE incorrectly handled long
passwords in SPICE tickets. An attacker could use this issue to cause the
SPICE server to crash, resulting in a denial of service." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2027-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2027-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(13\\.10|13\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libspice-server1:i386", ver: "0.12.4-0nocelt1ubuntu0.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "libspice-server1:i386", ver: "0.12.2-0nocelt2expubuntu1.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

