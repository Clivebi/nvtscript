if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841664" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-23 13:26:34 +0530 (Mon, 23 Dec 2013)" );
	script_cve_id( "CVE-2013-4549" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for qt4-x11 USN-2057-1" );
	script_tag( name: "affected", value: "qt4-x11 on Ubuntu 13.10,
  Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that QXmlSimpleReader in Qt incorrectly
handled XML entity expansion. An attacker could use this flaw to cause Qt
applications to consume large amounts of resources, resulting in a denial of
service." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2057-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2057-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qt4-x11'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|12\\.04 LTS|13\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "libqt4-xml", ver: "4:4.8.3+dfsg-0ubuntu3.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libqt4-xml", ver: "4:4.8.1-0ubuntu4.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libqt4-xml:i386", ver: "4:4.8.4+dfsg-0ubuntu18.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libqt5xml5:i386", ver: "5.0.2+dfsg1-7ubuntu11.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "libqt4-xml:i386", ver: "4:4.8.4+dfsg-0ubuntu9.5", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libqt5xml5:i386", ver: "5.0.1+dfsg-0ubuntu4.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

