if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1621-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841207" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-06 17:48:44 +0530 (Tue, 06 Nov 2012)" );
	script_cve_id( "CVE-2012-3144", "CVE-2012-3147", "CVE-2012-3149", "CVE-2012-3150", "CVE-2012-3156", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163", "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177", "CVE-2012-3180", "CVE-2012-3197" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1621-1" );
	script_name( "Ubuntu Update for mysql-5.5 USN-1621-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1621-1" );
	script_tag( name: "affected", value: "mysql-5.5 on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in MySQL and this update includes
  new upstream MySQL versions to fix these issues.

  MySQL has been updated to 5.1.66 in Ubuntu 10.04 LTS and Ubuntu 11.10.
  Ubuntu 12.04 LTS and Ubuntu 12.10 have been updated to MySQL 5.5.28.

  In addition to security fixes, the updated packages contain bug fixes, new
  features, and possibly incompatible changes.

  Please see the references for more information." );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html" );
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
	if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.28-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.1", ver: "5.1.66-0ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.1", ver: "5.1.66-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.28-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

