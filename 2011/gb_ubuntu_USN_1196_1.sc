if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1196-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840729" );
	script_version( "2021-05-19T13:10:04+0000" );
	script_tag( name: "last_modification", value: "2021-05-19 13:10:04 +0000 (Wed, 19 May 2021)" );
	script_tag( name: "creation_date", value: "2011-08-27 16:37:49 +0200 (Sat, 27 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:03:00 +0000 (Wed, 09 Oct 2019)" );
	script_xref( name: "USN", value: "1196-1" );
	script_cve_id( "CVE-2011-3145" );
	script_name( "Ubuntu Update for ecryptfs-utils USN-1196-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1196-1" );
	script_tag( name: "affected", value: "ecryptfs-utils on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that eCryptfs incorrectly handled permissions when
  modifying the mtab file. A local attacker could use this flaw to manipulate
  the mtab file, and possibly unmount arbitrary locations, leading to a
  denial of service." );
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
	if(( res = isdpkgvuln( pkg: "ecryptfs-utils", ver: "83-0ubuntu3.2.10.10.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ecryptfs-utils", ver: "83-0ubuntu3.2.10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "ecryptfs-utils", ver: "87-0ubuntu1.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

