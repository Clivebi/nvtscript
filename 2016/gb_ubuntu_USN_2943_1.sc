if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842704" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-11 12:47:23 +0530 (Mon, 11 Apr 2016)" );
	script_cve_id( "CVE-2014-9769", "CVE-2015-2325", "CVE-2015-2326", "CVE-2015-2327", "CVE-2015-2328", "CVE-2015-3210", "CVE-2015-5073", "CVE-2015-8380", "CVE-2015-8381", "CVE-2015-8382", "CVE-2015-8383", "CVE-2015-8384", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8388", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8392", "CVE-2015-8393", "CVE-2015-8394", "CVE-2015-8395", "CVE-2016-1283", "CVE-2016-3191" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for pcre3 USN-2943-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pcre3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code." );
	script_tag( name: "affected", value: "pcre3 on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2943-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2943-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libpcre3", ver: "1:8.31-2ubuntu2.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpcre3", ver: "8.12-4ubuntu0.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libpcre3", ver: "2:8.35-7.1ubuntu1.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

