if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1715-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841309" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-08 10:18:51 +0530 (Fri, 08 Feb 2013)" );
	script_cve_id( "CVE-2013-0247" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1715-1" );
	script_name( "Ubuntu Update for keystone USN-1715-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'keystone'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10)" );
	script_tag( name: "affected", value: "keystone on Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Dan Prince discovered that Keystone did not properly perform input
  validation when handling certain error conditions. An unauthenticated user
  could exploit this to cause a denial of service in Keystone API servers via
  disk space exhaustion." );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-keystone", ver: "2012.1+stable~20120824-a16a0ab9-0ubuntu2.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "python-keystone", ver: "2012.2.1-0ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

