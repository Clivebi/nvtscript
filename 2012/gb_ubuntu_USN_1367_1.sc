if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1367-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840897" );
	script_version( "2020-04-21T06:28:23+0000" );
	script_tag( name: "last_modification", value: "2020-04-21 06:28:23 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-02-21 18:59:42 +0530 (Tue, 21 Feb 2012)" );
	script_cve_id( "CVE-2009-5063", "CVE-2011-3026" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1367-1" );
	script_name( "Ubuntu Update for libpng USN-1367-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1367-1" );
	script_tag( name: "affected", value: "libpng on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that libpng did not properly verify the embedded profile
  length of iCCP chunks. An attacker could exploit this to cause a denial of
  service via application crash. This issue only affected Ubuntu 8.04 LTS.
  (CVE-2009-5063)

  Jueri Aedla discovered that libpng did not properly verify the size used
  when allocating memory during chunk decompression. If a user or automated
  system using libpng were tricked into opening a specially crafted image,
  an attacker could exploit this to cause a denial of service or execute
  code with the privileges of the user invoking the program. (CVE-2011-3026)" );
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
	if(( res = isdpkgvuln( pkg: "libpng12-0", ver: "1.2.44-1ubuntu0.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpng12-0", ver: "1.2.42-1ubuntu2.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libpng12-0", ver: "1.2.44-1ubuntu3.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpng12-0", ver: "1.2.15~beta5-3ubuntu0.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

