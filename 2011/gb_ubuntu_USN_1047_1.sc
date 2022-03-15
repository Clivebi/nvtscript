if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1047-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840572" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-31 15:15:14 +0100 (Mon, 31 Jan 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "USN", value: "1047-1" );
	script_cve_id( "CVE-2010-4369" );
	script_name( "Ubuntu Update for awstats vulnerability USN-1047-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|6\\.06 LTS|10\\.04 LTS|8\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1047-1" );
	script_tag( name: "affected", value: "awstats vulnerability on Ubuntu 6.06 LTS,
  Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that AWStats did not correctly filter the LoadPlugin
  configuration option. A local attacker on a shared system could use this
  to inject arbitrary code into AWStats." );
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
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "awstats", ver: "6.9~dfsg-1ubuntu3.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU6.06 LTS"){
	if(( res = isdpkgvuln( pkg: "awstats", ver: "6.5-1ubuntu1.4", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "awstats", ver: "6.9~dfsg-1ubuntu3.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "awstats", ver: "6.7.dfsg-1ubuntu0.2", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "awstats", ver: "6.9.5~dfsg-3ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

