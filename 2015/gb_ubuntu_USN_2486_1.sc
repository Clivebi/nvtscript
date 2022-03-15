if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842076" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-28 06:10:59 +0100 (Wed, 28 Jan 2015)" );
	script_cve_id( "CVE-2014-3566", "CVE-2014-6587", "CVE-2014-6601", "CVE-2015-0395", "CVE-2015-0408", "CVE-2015-0412", "CVE-2014-6585", "CVE-2014-6591", "CVE-2015-0400", "CVE-2015-0407", "CVE-2014-6593", "CVE-2015-0383", "CVE-2015-0410" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for openjdk-6 USN-2486-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-6'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the
OpenJDK JRE related to information disclosure, data integrity and availability. An
attacker could exploit these to cause a denial of service or expose sensitive data
over the network. (CVE-2014-3566, CVE-2014-6587, CVE-2014-6601, CVE-2015-0395,
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
(CVE-2015-0410)" );
	script_tag( name: "affected", value: "openjdk-6 on Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2486-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2486-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|10\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b34-1.13.6-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b34-1.13.6-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b34-1.13.6-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b34-1.13.6-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b34-1.13.6-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b34-1.13.6-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b34-1.13.6-1ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b34-1.13.6-1ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b34-1.13.6-1ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b34-1.13.6-1ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b34-1.13.6-1ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

