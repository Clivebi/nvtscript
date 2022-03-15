if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842843" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-02 10:56:43 +0530 (Tue, 02 Aug 2016)" );
	script_cve_id( "CVE-2016-3587", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610", "CVE-2016-3458", "CVE-2016-3500", "CVE-2016-3508", "CVE-2016-3550" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-8 USN-3043-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered
  in the OpenJDK JRE related to information disclosure, data integrity, and
  availability. An attacker could exploit these to cause a denial of service,
  expose sensitive data over the network, or possibly execute arbitrary code.
  (CVE-2016-3587, CVE-2016-3598, CVE-2016-3606, CVE-2016-3610)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. An attacker could exploit this to expose sensitive data
over the network or possibly execute arbitrary code. (CVE-2016-3458)

Multiple vulnerabilities were discovered in the OpenJDK JRE related
to availability. An attacker could exploit these to cause a denial
of service. (CVE-2016-3500, CVE-2016-3508)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit this to expose
sensitive data over the network. (CVE-2016-3550)" );
	script_tag( name: "affected", value: "openjdk-8 on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3043-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3043-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:i386", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:amd64", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:i386", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:amd64", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:i386", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:amd64", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:i386", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:amd64", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:i386", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:amd64", ver: "8u91-b14-3ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

