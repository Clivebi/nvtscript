if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841583" );
	script_version( "2021-07-02T02:00:36+0000" );
	script_tag( name: "last_modification", value: "2021-07-02 02:00:36 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-10-03 10:21:28 +0530 (Thu, 03 Oct 2013)" );
	script_cve_id( "CVE-2013-4256", "CVE-2013-4257" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for nas USN-1986-1" );
	script_tag( name: "affected", value: "nas on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Hamid Zamani discovered multiple security issues in the Network Audio
System (NAS) server. An attacker could possibly use these issues to cause a
denial of service or execute arbitrary code. (CVE-2013-4256, CVE-2013-4257)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1986-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1986-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nas'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "nas", ver: "1.9.3-4ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "nas", ver: "1.9.3-5ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "nas", ver: "1.9.3-5ubuntu0.13.04.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

