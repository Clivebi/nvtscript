if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841399" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-04-19 10:08:56 +0530 (Fri, 19 Apr 2013)" );
	script_cve_id( "CVE-2012-2942", "CVE-2013-1912" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for haproxy USN-1800-1" );
	script_xref( name: "USN", value: "1800-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1800-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'haproxy'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|12\\.10)" );
	script_tag( name: "affected", value: "haproxy on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that HAProxy incorrectly handled configurations where
  global.tune.bufsize was set to a value higher than the default. A remote
  attacker could use this issue to cause a denial of service, or possibly
  execute arbitrary code. (CVE-2012-2942)

  Yves Lafon discovered that HAProxy incorrectly handled HTTP keywords in TCP
  inspection rules when HTTP keep-alive is enabled. A remote attacker could
  use this issue to cause a denial of service, or possibly execute arbitrary
  code. (CVE-2013-1912)" );
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
	if(( res = isdpkgvuln( pkg: "haproxy", ver: "1.4.18-0ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "haproxy", ver: "1.4.15-1ubuntu0.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "haproxy", ver: "1.4.18-0ubuntu2.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

