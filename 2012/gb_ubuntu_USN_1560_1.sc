if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1560-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841136" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-11 09:38:22 +0530 (Tue, 11 Sep 2012)" );
	script_cve_id( "CVE-2012-3442", "CVE-2012-3443", "CVE-2012-3444" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1560-1" );
	script_name( "Ubuntu Update for python-django USN-1560-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1560-1" );
	script_tag( name: "affected", value: "python-django on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Django incorrectly validated the scheme of a
  redirect target. If a user were tricked into opening a specially crafted
  URL, an attacker could possibly exploit this to conduct cross-site
  scripting (XSS) attacks. (CVE-2012-3442)

  It was discovered that Django incorrectly handled validating certain
  images. A remote attacker could use this flaw to cause the server to
  consume memory, leading to a denial of service. (CVE-2012-3443)

  Jeroen Dekkers discovered that Django incorrectly handled certain image
  dimensions. A remote attacker could use this flaw to cause the server to
  consume resources, leading to a denial of service. (CVE-2012-3444)" );
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
	if(( res = isdpkgvuln( pkg: "python-django", ver: "1.1.1-2ubuntu1.5", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-django", ver: "1.3.1-4ubuntu1.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "python-django", ver: "1.3-2ubuntu1.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "python-django", ver: "1.2.5-1ubuntu1.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

