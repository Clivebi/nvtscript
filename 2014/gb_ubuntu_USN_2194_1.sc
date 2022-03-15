if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841808" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-12 09:13:06 +0530 (Mon, 12 May 2014)" );
	script_cve_id( "CVE-2014-0056" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for neutron USN-2194-1" );
	script_tag( name: "affected", value: "neutron on Ubuntu 13.10" );
	script_tag( name: "insight", value: "Aaron Rosen discovered that OpenStack Neutron did not properly
perform authorization checks when creating ports when using plugins relying on
the l3-agent. A remote authenticated attacker could exploit this to access the
network of other tenants." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2194-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2194-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'neutron'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU13\\.10" );
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
	if(( res = isdpkgvuln( pkg: "python-neutron", ver: "1:2013.2.3-0ubuntu1.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

