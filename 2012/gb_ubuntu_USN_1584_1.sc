if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1584-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841164" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-27 09:07:45 +0530 (Thu, 27 Sep 2012)" );
	script_cve_id( "CVE-2012-4037" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1584-1" );
	script_name( "Ubuntu Update for transmission USN-1584-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1584-1" );
	script_tag( name: "affected", value: "transmission on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Justin C. Klein Keane discovered that the Transmission web client
  incorrectly escaped certain strings. If a user were tricked into opening a
  specially crafted torrent file, an attacker could possibly exploit this to
  conduct cross-site scripting (XSS) attacks." );
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
	if(( res = isdpkgvuln( pkg: "transmission-common", ver: "2.51-0ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

