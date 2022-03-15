if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1643-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841232" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-04 09:48:16 +0530 (Tue, 04 Dec 2012)" );
	script_cve_id( "CVE-2011-2939", "CVE-2011-3597", "CVE-2012-5195", "CVE-2012-5526" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1643-1" );
	script_name( "Ubuntu Update for perl USN-1643-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|8\\.04 LTS|12\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1643-1" );
	script_tag( name: "affected", value: "perl on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the decode_xs function in the Encode module is
  vulnerable to a heap-based buffer overflow via a crafted Unicode string.
  An attacker could use this overflow to cause a denial of service.
  (CVE-2011-2939)

  It was discovered that the 'new' constructor in the Digest module is
  vulnerable to an eval injection. An attacker could use this to execute
  arbitrary code. (CVE-2011-3597)

  It was discovered that Perl's 'x' string repeat operator is vulnerable
  to a heap-based buffer overflow. An attacker could use this to execute
  arbitrary code. (CVE-2012-5195)

  Ryo Anazawa discovered that the CGI.pm module does not properly escape
  newlines in Set-Cookie or P3P (Platform for Privacy Preferences Project)
  headers. An attacker could use this to inject arbitrary headers into
  responses from applications that use CGI.pm. (CVE-2012-5526)" );
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
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.14.2-6ubuntu2.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.12.4-4ubuntu0.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.10.1-8ubuntu2.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.8.8-12ubuntu0.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "make", ver: "all the necessary changes.", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.14.2-13ubuntu0.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

