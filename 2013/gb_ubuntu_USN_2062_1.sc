if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841663" );
	script_version( "2021-03-12T08:02:45+0000" );
	script_tag( name: "last_modification", value: "2021-03-12 08:02:45 +0000 (Fri, 12 Mar 2021)" );
	script_tag( name: "creation_date", value: "2013-12-23 13:25:29 +0530 (Mon, 23 Dec 2013)" );
	script_cve_id( "CVE-2013-6858" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Ubuntu Update for horizon USN-2062-1" );
	script_tag( name: "affected", value: "horizon on Ubuntu 13.10,
  Ubuntu 13.04,
  Ubuntu 12.10" );
	script_tag( name: "insight", value: "Chris Chapman discovered cross-site scripting (XSS)
vulnerabilities in Horizon via the Volumes and Network Topology pages.
An authenticated attacker could exploit these to conduct stored cross-site
scripting (XSS) attacks against users viewing these pages in order to modify
the contents or steal confidential data within the same domain." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2062-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2062-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'horizon'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|13\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "python-django-horizon", ver: "2012.2.4-0ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "python-django-horizon", ver: "1:2013.2-0ubuntu1.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "python-django-horizon", ver: "1:2013.1.4-0ubuntu1.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

