if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842548" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-04 06:12:57 +0100 (Fri, 04 Dec 2015)" );
	script_cve_id( "CVE-2015-4805", "CVE-2015-4835", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4881", "CVE-2015-4883", "CVE-2015-4806", "CVE-2015-4872", "CVE-2015-4734", "CVE-2015-4842", "CVE-2015-4903", "CVE-2015-4803", "CVE-2015-4893", "CVE-2015-4911", "CVE-2015-4882" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-6 USN-2827-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-6'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in
the OpenJDK JRE related to information disclosure, data integrity and availability.
An attacker could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2015-4805, CVE-2015-4835, CVE-2015-4843,
CVE-2015-4844, CVE-2015-4860, CVE-2015-4881, CVE-2015-4883)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
this to expose sensitive data over the network. (CVE-2015-4806)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. An attacker could exploit this expose sensitive data over
the network. (CVE-2015-4872)

Multiple vulnerabilities were discovered in the OpenJDK JRE related
to information disclosure. An attacker could exploit these to expose
sensitive data over the network. (CVE-2015-4734, CVE-2015-4842,
CVE-2015-4903)

Multiple vulnerabilities were discovered in the OpenJDK JRE related
to availability. An attacker could exploit these to cause a denial of
service. (CVE-2015-4803, CVE-2015-4893, CVE-2015-4911)" );
	script_tag( name: "affected", value: "openjdk-6 on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2827-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2827-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b37-1.13.9-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b37-1.13.9-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b37-1.13.9-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b37-1.13.9-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b37-1.13.9-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b37-1.13.9-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

