if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843505" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-20 09:13:25 +0200 (Fri, 20 Apr 2018)" );
	script_cve_id( "CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1303", "CVE-2018-1312" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 08:15:00 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for apache2 USN-3627-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Alex Nichols and Jakob Hirsch discovered
  that the Apache HTTP Server mod_authnz_ldap module incorrectly handled missing
  charset encoding headers. A remote attacker could possibly use this issue to
  cause the server to crash, resulting in a denial of service. (CVE-2017-15710)
  Elar Lang discovered that the Apache HTTP Server incorrectly handled certain
  characters specified in FilesMatch . A remote attacker could possibly use this
  issue to upload certain files, contrary to expectations. (CVE-2017-15715) It was
  discovered that the Apache HTTP Server mod_session module incorrectly handled
  certain headers. A remote attacker could possibly use this issue to influence
  session data. (CVE-2018-1283) Robert Swiecki discovered that the Apache HTTP
  Server incorrectly handled certain requests. A remote attacker could possibly
  use this issue to cause the server to crash, leading to a denial of service.
  (CVE-2018-1301) Robert Swiecki discovered that the Apache HTTP Server
  mod_cache_socache module incorrectly handled certain headers. A remote attacker
  could possibly use this issue to cause the server to crash, leading to a denial
  of service. (CVE-2018-1303) Nicolas Daniels discovered that the Apache HTTP
  Server incorrectly generated the nonce when creating HTTP Digest authentication
  challenges. A remote attacker could possibly use this issue to replay HTTP
  requests across a cluster of servers. (CVE-2018-1312)" );
	script_tag( name: "affected", value: "apache2 on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3627-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3627-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.7-1ubuntu4.20", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.27-2ubuntu4.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.18-2ubuntu3.8", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

