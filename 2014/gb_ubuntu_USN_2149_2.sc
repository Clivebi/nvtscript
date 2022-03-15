if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841755" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-20 09:49:31 +0530 (Thu, 20 Mar 2014)" );
	script_cve_id( "CVE-2013-1881" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for gtk+3.0 USN-2149-2" );
	script_tag( name: "affected", value: "gtk+3.0 on Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "USN-2149-1 fixed a vulnerability in librsvg. This update
provides a compatibility fix for GTK+ to work with the librsvg security update.

Original advisory details:

It was discovered that librsvg would load XML external entities by default.
If a user were tricked into viewing a specially crafted SVG file, an
attacker could possibly obtain access to arbitrary files." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2149-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2149-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gtk+3.0'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libgtk-3-0", ver: "3.4.2-0ubuntu0.7", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libgtk-3-0", ver: "3.6.0-0ubuntu3.3", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

