if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841511" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-08-08 11:42:01 +0530 (Thu, 08 Aug 2013)" );
	script_cve_id( "CVE-2013-4160" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for lcms2 USN-1911-1" );
	script_tag( name: "affected", value: "lcms2 on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that Little CMS did not properly verify certain memory
allocations. If a user or automated system using Little CMS were tricked
into opening a specially crafted file, an attacker could cause Little CMS
to crash." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1911-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1911-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lcms2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "liblcms2-2", ver: "2.2+git20110628-2ubuntu3.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "liblcms2-2", ver: "2.2+git20110628-2ubuntu4.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "liblcms2-2", ver: "2.4-0ubuntu3.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

