if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1399-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840931" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-16 10:50:07 +0530 (Fri, 16 Mar 2012)" );
	script_cve_id( "CVE-2012-0943" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1399-2" );
	script_name( "Ubuntu Update for lightdm USN-1399-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1399-2" );
	script_tag( name: "affected", value: "lightdm on Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Ryan Lortie discovered that a guest session script bundled in the Light
  Display Manager package improperly cleaned out certain guest session files.
  A local attacker could use this issue to delete arbitrary files." );
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
	if(( res = isdpkgvuln( pkg: "lightdm", ver: "1.0.6-0ubuntu1.6", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

