if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843226" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-27 06:59:33 +0200 (Tue, 27 Jun 2017)" );
	script_cve_id( "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for apache2 USN-3340-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Emmanuel Dreyfus discovered that third-party
  modules using the ap_get_basic_auth_pw() function outside of the authentication
  phase may lead to authentication requirements being bypassed. This update adds a
  new ap_get_basic_auth_components() function for use by third-party modules.
  (CVE-2017-3167) Vasileios Panopoulos discovered that the Apache mod_ssl module
  may crash when third-party modules call ap_hook_process_connection() during an
  HTTP request to an HTTPS port. (CVE-2017-3169) Javier Jim&#233 nez discovered
  that the Apache HTTP Server incorrectly handled parsing certain requests. A
  remote attacker could possibly use this issue to cause the Apache HTTP Server to
  crash, resulting in a denial of service. (CVE-2017-7668) ChenQin and Hanno
  B&#246 ck discovered that the Apache mod_mime module incorrectly handled certain
  Content-Type response headers. A remote attacker could possibly use this issue
  to cause the Apache HTTP Server to crash, resulting in a denial of service.
  (CVE-2017-7679)" );
	script_tag( name: "affected", value: "apache2 on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3340-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3340-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.7-1ubuntu4.16", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.25-3ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.18-2ubuntu4.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.18-2ubuntu3.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

