if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1050-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840596" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1050-1" );
	script_cve_id( "CVE-2010-1585", "CVE-2011-0053", "CVE-2011-0061", "CVE-2011-0062" );
	script_name( "Ubuntu Update for thunderbird vulnerabilities USN-1050-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1050-1" );
	script_tag( name: "affected", value: "thunderbird vulnerabilities on Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Jesse Ruderman, Igor Bukanov, Olli Pettay, Gary Kwong, Jeff Walden, Henry
  Sivonen, Martijn Wargers, David Baron and Marcia Knous discovered several
  memory issues in the browser engine. An attacker could exploit these to
  crash the browser or possibly run arbitrary code as the user invoking the
  program. (CVE-2011-0053, CVE-2011-0062)

  Roberto Suggi Liverani discovered a possible issue with unsafe JavaScript
  execution in chrome documents. A malicious extension could exploit this to
  execute arbitrary code with chrome privlieges. (CVE-2010-1585)

  Jordi Chancel discovered a buffer overflow in the JPEG decoding engine. An
  attacker could exploit this to crash the browser or possibly run arbitrary
  code as the user invoking the program. (CVE-2011-0061)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird-dbg", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird-dev", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird-gnome-support-dbg", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird-gnome-support", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird-dbg", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird-dev", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird-gnome-support-dbg", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird-gnome-support", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "3.1.8+build3+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

