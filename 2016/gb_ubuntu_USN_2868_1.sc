if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842600" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-14 05:41:07 +0100 (Thu, 14 Jan 2016)" );
	script_cve_id( "CVE-2015-8605" );
	script_tag( name: "cvss_base", value: "5.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for isc-dhcp USN-2868-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'isc-dhcp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sebastian Poehn discovered that the DHCP
  server, client, and relay incorrectly handled certain malformed UDP packets.
  A remote attacker could use this issue to cause the DHCP server, client, or
  relay to stop responding, resulting in a denial of service." );
	script_tag( name: "affected", value: "isc-dhcp on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2868-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2868-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.3.1-5ubuntu2.3", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.3.1-5ubuntu2.3", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.3.1-5ubuntu2.3", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.3.1-5ubuntu2.3", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.2.4-7ubuntu12.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.2.4-7ubuntu12.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.2.4-7ubuntu12.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.2.4-7ubuntu12.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.1.ESV-R4-0ubuntu5.10", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.1.ESV-R4-0ubuntu5.10", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.1.ESV-R4-0ubuntu5.10", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.1.ESV-R4-0ubuntu5.10", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.3.1-5ubuntu3.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.3.1-5ubuntu3.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.3.1-5ubuntu3.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.3.1-5ubuntu3.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

