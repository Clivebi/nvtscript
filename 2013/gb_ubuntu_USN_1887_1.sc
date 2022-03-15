if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841485" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-06-24 15:06:42 +0530 (Mon, 24 Jun 2013)" );
	script_cve_id( "CVE-2012-4406", "CVE-2013-2161" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Ubuntu Update for swift USN-1887-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10|13\\.04)" );
	script_xref( name: "USN", value: "1887-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1887-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'swift'
  package(s) announced via the referenced advisory." );
	script_tag( name: "affected", value: "swift on Ubuntu 13.04,

  Ubuntu 12.10,

  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Sebastian Krahmer discovered that Swift used the loads function in the
  pickle Python module when it was configured to use memcached. A remote
  attacker on the same network as memcached could exploit this to execute
  arbitrary code. This update adds a new memcache_serialization_support
  option to support secure json serialization. For details on this new
  option, please see /usr/share/doc/swift-proxy/memcache.conf-sample. This
  issue only affected Ubuntu 12.04 LTS. (CVE-2012-4406)

  Alex Gaynor discovered that Swift did not safely generate XML. An
  attacker could potentially craft an account name to generate arbitrary XML
  responses to trigger vulnerabilities in software parsing Swift's XML.
  (CVE-2013-2161)" );
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
	if(( res = isdpkgvuln( pkg: "python-swift", ver: "1.4.8-0ubuntu2.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "python-swift", ver: "1.7.4-0ubuntu2.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "python-swift", ver: "1.8.0-0ubuntu1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

