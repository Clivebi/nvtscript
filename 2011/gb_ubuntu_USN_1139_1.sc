if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1139-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840669" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1139-1" );
	script_cve_id( "CVE-2010-3762", "CVE-2011-1910" );
	script_name( "Ubuntu Update for bind9 USN-1139-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1139-1" );
	script_tag( name: "affected", value: "bind9 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Bind incorrectly handled certain bad signatures if
  multiple trust anchors existed for a single zone. A remote attacker could
  use this flaw to cause Bind to stop responding, resulting in a denial of
  service. This issue only affected Ubuntu 8.04 LTS and 10.04 LTS.
  (CVE-2010-3762)

  Frank Kloeker and Michael Sinatra discovered that Bind incorrectly handled
  certain very large RRSIG RRsets included in negative responses. A remote
  attacker could use this flaw to cause Bind to stop responding, resulting in
  a denial of service. (CVE-2011-1910)" );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "libdns66", ver: "1:9.7.1.dfsg.P2-2ubuntu0.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libdns64", ver: "1:9.7.0.dfsg.P1-1ubuntu0.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libdns69", ver: "1:9.7.3.dfsg-1ubuntu2.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libdns36", ver: "1:9.4.2.dfsg.P2-2ubuntu0.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

