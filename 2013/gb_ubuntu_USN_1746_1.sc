if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1746-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841342" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-01 11:08:26 +0530 (Fri, 01 Mar 2013)" );
	script_cve_id( "CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1746-1" );
	script_name( "Ubuntu Update for pidgin USN-1746-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "affected", value: "pidgin on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Chris Wysopal discovered that Pidgin incorrectly handled file transfers in
  the MXit protocol handler. A remote attacker could use this issue to create
  or overwrite arbitrary files. This issue only affected Ubuntu 11.10,
  Ubuntu 12.04 LTS and Ubuntu 12.10. (CVE-2013-0271)

  It was discovered that Pidgin incorrectly handled long HTTP headers in the
  MXit protocol handler. A malicious remote server could use this issue to
  execute arbitrary code. (CVE-2013-0272)

  It was discovered that Pidgin incorrectly handled long user IDs in the
  Sametime protocol handler. A malicious remote server could use this issue
  to cause Pidgin to crash, resulting in a denial of service. (CVE-2013-0273)

  It was discovered that Pidgin incorrectly handled long strings when
  processing UPnP responses. A remote attacker could use this issue to cause
  Pidgin to crash, resulting in a denial of service. (CVE-2013-0274)" );
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
	if(( res = isdpkgvuln( pkg: "libpurple0", ver: "1:2.10.3-0ubuntu1.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pidgin", ver: "1:2.10.3-0ubuntu1.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "libpurple0", ver: "1:2.10.0-0ubuntu2.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pidgin", ver: "1:2.10.0-0ubuntu2.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpurple0", ver: "1:2.6.6-1ubuntu4.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pidgin", ver: "1:2.6.6-1ubuntu4.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libpurple0", ver: "1:2.10.6-0ubuntu2.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "pidgin", ver: "1:2.10.6-0ubuntu2.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

