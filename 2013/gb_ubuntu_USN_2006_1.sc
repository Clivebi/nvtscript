if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841596" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-29 16:18:35 +0530 (Tue, 29 Oct 2013)" );
	script_cve_id( "CVE-2013-3839", "CVE-2013-5807" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_name( "Ubuntu Update for mysql-5.5 USN-2006-1" );
	script_tag( name: "affected", value: "mysql-5.5 on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.1.72 in Ubuntu 10.04 LTS. Ubuntu 12.04 LTS,
Ubuntu 12.10, Ubuntu 13.04 and Ubuntu 13.10 have been updated to
MySQL 5.5.34.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the references for more information." );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-72.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-34.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2006-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2006-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-5.5'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|10\\.04 LTS|12\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.34-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.1", ver: "5.1.72-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.34-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.34-0ubuntu0.13.04.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

