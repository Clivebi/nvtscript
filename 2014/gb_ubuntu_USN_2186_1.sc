if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841800" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-05 11:25:19 +0530 (Mon, 05 May 2014)" );
	script_cve_id( "CVE-2013-7374" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for indicator-datetime USN-2186-1" );
	script_tag( name: "affected", value: "indicator-datetime on Ubuntu 13.10" );
	script_tag( name: "insight", value: "It was discovered that the Date and Time Indicator incorrectly
allowed Evolution to be opened at the greeter screen. An attacker could use this
issue to possibly gain unexpected access to applications such as a web
browser with privileges of the greeter user." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2186-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2186-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'indicator-datetime'
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
	if(( res = isdpkgvuln( pkg: "indicator-datetime", ver: "13.10.0+13.10.20131023.2-0ubuntu1.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

