if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842078" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-28 06:11:16 +0100 (Wed, 28 Jan 2015)" );
	script_cve_id( "CVE-2014-3566", "CVE-2014-6587", "CVE-2014-6601", "CVE-2015-0395", "CVE-2015-0408", "CVE-2015-0412", "CVE-2014-6585", "CVE-2014-6591", "CVE-2015-0400", "CVE-2015-0407", "CVE-2014-6593", "CVE-2015-0383", "CVE-2015-0410", "CVE-2015-0413" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for openjdk-7 USN-2487-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in
the OpenJDK JRE related to information disclosure, data integrity and availability.
An attacker could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2014-3566, CVE-2014-6587, CVE-2014-6601, CVE-2015-0395,
CVE-2015-0408, CVE-2015-0412)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2014-6585, CVE-2014-6591, CVE-2015-0400,
CVE-2015-0407)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and integrity. An attacker could exploit this to
expose sensitive data over the network. (CVE-2014-6593)

A vulnerability was discovered in the OpenJDK JRE related to integrity and
availability. An attacker could exploit this to cause a denial of service.
(CVE-2015-0383)

A vulnerability was discovered in the OpenJDK JRE related to availability.
An attacker could this exploit to cause a denial of service.
(CVE-2015-0410)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. (CVE-2015-0413)" );
	script_tag( name: "affected", value: "openjdk-7 on Ubuntu 14.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2487-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2487-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:amd64", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:i386", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:amd64", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:i386", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:amd64", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:i386", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:amd64", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:i386", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-source", ver: "7u75-2.5.4-1~utopic1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:amd64", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:i386", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:amd64", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:i386", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:i386", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:amd64", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:amd64", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:i386", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-source", ver: "7u75-2.5.4-1~trusty1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

