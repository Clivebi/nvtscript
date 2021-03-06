if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1521-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841098" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-03 11:17:43 +0530 (Fri, 03 Aug 2012)" );
	script_cve_id( "CVE-2012-3422", "CVE-2012-3423" );
	script_xref( name: "USN", value: "1521-1" );
	script_name( "Ubuntu Update for icedtea-web USN-1521-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1521-1" );
	script_tag( name: "affected", value: "icedtea-web on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Chamal De Silva discovered that the IcedTea-Web Java web browser
  plugin could dereference an uninitialized pointer. A remote attacker
  could use this to craft a malicious web page that could cause a
  denial of service by crashing the web browser or possibly execute
  arbitrary code. (CVE-2012-3422)

  Steven Bergom and others discovered that the IcedTea-Web Java web
  browser plugin assumed that all strings provided by browsers are NULL
  terminated, which is not guaranteed by the NPAPI (Netscape Plugin
  Application Programming Interface). A remote attacker could use this
  to craft a malicious Java applet that could cause a denial of service
  by crashing the web browser, expose sensitive information or possibly
  execute arbitrary code. (CVE-2012-3423)" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2-2ubuntu0.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2-2ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-plugin", ver: "1.2-2ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2-2ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2-2ubuntu0.11.04.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

