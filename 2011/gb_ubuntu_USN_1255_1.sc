if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1255-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840800" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-11 09:55:33 +0530 (Fri, 11 Nov 2011)" );
	script_xref( name: "USN", value: "1255-1" );
	script_cve_id( "CVE-2011-2911", "CVE-2011-2912", "CVE-2011-2913", "CVE-2011-2914", "CVE-2011-2915" );
	script_name( "Ubuntu Update for libmodplug USN-1255-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1255-1" );
	script_tag( name: "affected", value: "libmodplug on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Hossein Lotfi discovered that libmodplug did not correctly handle certain
  malformed media files. If a user or automated system were tricked into
  opening a crafted media file, an attacker could cause a denial of service
  or possibly execute arbitrary code with privileges of the user invoking the
  program. (CVE-2011-2911, CVE-2011-2912, CVE-2011-2913)

  It was discovered that libmodplug did not correctly handle certain
  malformed media files. If a user or automated system were tricked into
  opening a crafted media file, an attacker could cause a denial of service
  or possibly execute arbitrary code with privileges of the user invoking the
  program. (CVE-2011-2914, CVE-2011-2915)" );
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
	if(( res = isdpkgvuln( pkg: "libmodplug1", ver: "1:0.8.8.1-1ubuntu1.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libmodplug0c2", ver: "1:0.8.7-1ubuntu0.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libmodplug1", ver: "1:0.8.8.1-2ubuntu0.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

