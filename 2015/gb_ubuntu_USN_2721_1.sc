if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842420" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-21 07:50:15 +0200 (Fri, 21 Aug 2015)" );
	script_cve_id( "CVE-2014-3580", "CVE-2014-8108", "CVE-2015-0202", "CVE-2015-0248", "CVE-2015-0251", "CVE-2015-3184", "CVE-2015-3187" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for subversion USN-2721-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'subversion'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Subversion
mod_dav_svn module incorrectly handled REPORT requests for a resource that does
not exist. A remote attacker could use this issue to cause the server to crash,
resulting in a denial of service. This issue only affected Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2014-3580)

It was discovered that the Subversion mod_dav_svn module incorrectly
handled requests requiring a lookup for a virtual transaction name that
does not exist. A remote attacker could use this issue to cause the server
to crash, resulting in a denial of service. This issue only affected Ubuntu
14.04 LTS. (CVE-2014-8108)

Evgeny Kotkov discovered that the Subversion mod_dav_svn module incorrectly
handled large numbers of REPORT requests. A remote attacker could use this
issue to cause the server to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-0202)

Evgeny Kotkov discovered that the Subversion mod_dav_svn and svnserve
modules incorrectly certain crafted parameter combinations. A remote
attacker could use this issue to cause the server to crash, resulting in a
denial of service. (CVE-2015-0248)

Ivan Zhakov discovered that the Subversion mod_dav_svn module incorrectly
handled crafted v1 HTTP protocol request sequences. A remote attacker could
use this issue to spoof the svn:author property. (CVE-2015-0251)

C. Michael Pilato discovered that the Subversion mod_dav_svn module
incorrectly restricted anonymous access. A remote attacker could use this
issue to read hidden files via the path name. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-3184)

C. Michael Pilato discovered that Subversion incorrectly handled path-based
authorization. A remote attacker could use this issue to obtain sensitive
path information. (CVE-2015-3187)" );
	script_tag( name: "affected", value: "subversion on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2721-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2721-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.8.8-1ubuntu3.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1:amd64", ver: "1.8.8-1ubuntu3.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1:i386", ver: "1.8.8-1ubuntu3.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "subversion", ver: "1.8.8-1ubuntu3.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.17dfsg-3ubuntu3.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.6.17dfsg-3ubuntu3.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "subversion", ver: "1.6.17dfsg-3ubuntu3.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

