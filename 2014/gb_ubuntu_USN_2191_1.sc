if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841796" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-05 11:24:25 +0530 (Mon, 05 May 2014)" );
	script_cve_id( "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0461", "CVE-2014-0462", "CVE-2014-2397", "CVE-2014-2405", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427", "CVE-2014-0453", "CVE-2014-0460", "CVE-2014-0459", "CVE-2014-1876", "CVE-2014-2398", "CVE-2014-2403" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for openjdk-6 USN-2191-1" );
	script_tag( name: "affected", value: "openjdk-6 on Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the OpenJDK JRE
related to information disclosure, data integrity and availability. An attacker
could exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2014-0429, CVE-2014-0446, CVE-2014-0451, CVE-2014-0452,
CVE-2014-0456, CVE-2014-0457, CVE-2014-0458, CVE-2014-0461, CVE-2014-0462,
CVE-2014-2397, CVE-2014-2405, CVE-2014-2412, CVE-2014-2414, CVE-2014-2421,
CVE-2014-2423, CVE-2014-2427)

Two vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to expose sensitive data over the network. (CVE-2014-0453, CVE-2014-0460)

A vulnerability was discovered in the OpenJDK JRE related to availability.
An attacker could exploit this to cause a denial of service.
(CVE-2014-0459)

Jakub Wilk discovered that the OpenJDK JRE incorrectly handled temporary
files. A local attacker could possibly use this issue to overwrite
arbitrary files. In the default installation of Ubuntu, this should be
prevented by the Yama link restrictions. (CVE-2014-1876)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. (CVE-2014-2398)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure. An attacker could exploit this to expose sensitive data over
the network. (CVE-2014-2403)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2191-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2191-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-6'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b31-1.13.3-1ubuntu1~0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b31-1.13.3-1ubuntu1~0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b31-1.13.3-1ubuntu1~0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b31-1.13.3-1ubuntu1~0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b31-1.13.3-1ubuntu1~0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b31-1.13.3-1ubuntu1~0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b31-1.13.3-1ubuntu1~0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b31-1.13.3-1ubuntu1~0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b31-1.13.3-1ubuntu1~0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b31-1.13.3-1ubuntu1~0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b31-1.13.3-1ubuntu1~0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

