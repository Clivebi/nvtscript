if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1622-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841205" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-06 17:48:38 +0530 (Tue, 06 Nov 2012)" );
	script_cve_id( "CVE-2012-2103", "CVE-2012-3512", "CVE-2012-3513" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1622-1" );
	script_name( "Ubuntu Update for munin USN-1622-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1622-1" );
	script_tag( name: "affected", value: "munin on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the Munin qmailscan plugin incorrectly handled
  temporary files. A local attacker could use this issue to possibly
  overwrite arbitrary files. This issue only affected Ubuntu 10.04 LTS,
  Ubuntu 11.10, and Ubuntu 12.04 LTS. (CVE-2012-2103)

  It was discovered that Munin incorrectly handled plugin state file
  permissions. An attacker obtaining privileges of the munin user could use
  this issue to escalate privileges to root. (CVE-2012-3512)

  It was discovered that Munin incorrectly handled specifying an alternate
  configuration file. A remote attacker could possibly use this issue to
  execute arbitrary code with the privileges of the web server. This issue
  only affected Ubuntu 12.10. (CVE-2012-3513)" );
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
	if(( res = isdpkgvuln( pkg: "munin", ver: "1.4.6-3ubuntu3.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "munin", ver: "1.4.5-3ubuntu4.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "munin", ver: "1.4.4-1ubuntu1.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "munin", ver: "2.0.2-1ubuntu2.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

