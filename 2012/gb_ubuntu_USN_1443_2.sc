if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1443-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841031" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-08 10:14:01 +0530 (Fri, 08 Jun 2012)" );
	script_cve_id( "CVE-2012-0949", "CVE-2012-0950" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "USN", value: "1443-2" );
	script_name( "Ubuntu Update for update-manager USN-1443-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1443-2" );
	script_tag( name: "affected", value: "update-manager on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1443-1 fixed vulnerabilities in Update Manager. The fix for
  CVE-2012-0949 was discovered to be incomplete. This update fixes the
  problem.

  Original advisory details:

  Felix Geyer discovered that the Update Manager Apport hook incorrectly
  uploaded certain system state archive files to Launchpad when reporting
  bugs. This could possibly result in repository credentials being included
  in public bug reports. (CVE-2012-0949)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "update-manager-core", ver: "0.156.14.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "update-manager-core", ver: "0.152.25.12", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "update-manager-core", ver: "0.150.5.4", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

