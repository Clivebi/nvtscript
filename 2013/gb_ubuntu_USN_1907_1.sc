if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841509" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-08-01 19:12:51 +0530 (Thu, 01 Aug 2013)" );
	script_cve_id( "CVE-2013-1500", "CVE-2013-2454", "CVE-2013-2458", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2449", "CVE-2013-2452", "CVE-2013-2456", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2450", "CVE-2013-2448", "CVE-2013-2451", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-2453", "CVE-2013-2455", "CVE-2013-2457" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for openjdk-7 USN-1907-1" );
	script_tag( name: "affected", value: "openjdk-7 on Ubuntu 13.04,
Ubuntu 12.10" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the OpenJDK JRE
related to information disclosure and data integrity. An attacker could exploit
these to expose sensitive data over the network. (CVE-2013-1500, CVE-2013-2454,
CVE-2013-2458)

A vulnerability was discovered in the OpenJDK Javadoc related to data
integrity. (CVE-2013-1571)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and availability. An attacker could exploit this to cause a
denial of service or expose sensitive data over the network.
(CVE-2013-2407)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2013-2412, CVE-2013-2443, CVE-2013-2446,
CVE-2013-2447, CVE-2013-2449, CVE-2013-2452, CVE-2013-2456)

Several vulnerabilities were discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial of service.
(CVE-2013-2444, CVE-2013-2445, CVE-2013-2450)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2013-2448, CVE-2013-2451, CVE-2013-2459, CVE-2013-2460,
CVE-2013-2461, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469, CVE-2013-2470,
CVE-2013-2471, CVE-2013-2472, CVE-2013-2473)

Several vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2013-2453, CVE-2013-2455, CVE-2013-2457)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1907-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1907-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|13\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-cacao", ver: "7u25-2.3.10-1ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm", ver: "7u25-2.3.10-1ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-doc", ver: "7u25-2.3.10-1ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre", ver: "7u25-2.3.10-1ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless", ver: "7u25-2.3.10-1ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u25-2.3.10-1ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero", ver: "7u25-2.3.10-1ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm", ver: "7u25-2.3.10-1ubuntu0.13.04.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-doc", ver: "7u25-2.3.10-1ubuntu0.13.04.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre", ver: "7u25-2.3.10-1ubuntu0.13.04.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless", ver: "7u25-2.3.10-1ubuntu0.13.04.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u25-2.3.10-1ubuntu0.13.04.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero", ver: "7u25-2.3.10-1ubuntu0.13.04.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

