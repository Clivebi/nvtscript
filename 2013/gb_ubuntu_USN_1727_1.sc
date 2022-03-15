if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1727-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841328" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-22 10:12:49 +0530 (Fri, 22 Feb 2013)" );
	script_cve_id( "CVE-2013-0252" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1727-1" );
	script_name( "Ubuntu Update for boost1.49 USN-1727-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'boost1.49'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	script_tag( name: "affected", value: "boost1.49 on Ubuntu 12.10" );
	script_tag( name: "insight", value: "It was discovered that the Boost.Locale library incorrectly validated some
  invalid UTF-8 sequences. An attacker could possibly use this issue to
  bypass input validation in certain applications." );
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
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libboost-locale1.49.0", ver: "1.49.0-3.1ubuntu1.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

