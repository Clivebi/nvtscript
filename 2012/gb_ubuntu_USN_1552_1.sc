if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1552-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841130" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-04 11:39:22 +0530 (Tue, 04 Sep 2012)" );
	script_cve_id( "CVE-2012-3542", "CVE-2012-3426" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_xref( name: "USN", value: "1552-1" );
	script_name( "Ubuntu Update for keystone USN-1552-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1552-1" );
	script_tag( name: "affected", value: "keystone on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dolph Mathews discovered that OpenStack Keystone did not properly
  restrict to administrative users the ability to update users'
  tenants. A remote attacker that can reach the administrative API can
  use this to add any user to any tenant. (CVE-2012-3542)

  Derek Higgins discovered that OpenStack Keystone did not properly
  implement token expiration. A remote attacker could use this to
  continue to access an account that has been disabled or has a changed
  password. (CVE-2012-3426)" );
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
	if(( res = isdpkgvuln( pkg: "keystone", ver: "2012.1+stable~20120824-a16a0ab9-0ubuntu2.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python-keystone", ver: "2012.1+stable~20120824-a16a0ab9-0ubuntu2.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

