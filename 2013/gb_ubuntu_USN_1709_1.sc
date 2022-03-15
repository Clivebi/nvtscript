if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1709-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841300" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-01-31 09:26:59 +0530 (Thu, 31 Jan 2013)" );
	script_cve_id( "CVE-2013-0208" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1709-1" );
	script_name( "Ubuntu Update for nova USN-1709-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nova'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.10" );
	script_tag( name: "affected", value: "nova on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "insight", value: "Phil Day discovered that nova-volume did not validate access to volumes. An
  authenticated attacker could exploit this to bypass intended access
  controls and boot from arbitrary volumes." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "nova-volume", ver: "2011.3-0ubuntu6.11", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python-nova", ver: "2011.3-0ubuntu6.11", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

