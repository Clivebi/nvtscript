if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842952" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-18 05:33:01 +0100 (Fri, 18 Nov 2016)" );
	script_cve_id( "CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-7 USN-3130-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenJDK did not restrict the set of algorithms used
for Jar integrity verification. An attacker could use this to modify
without detection the content of a JAR file, affecting system integrity.
(CVE-2016-5542)

It was discovered that the JMX component of OpenJDK did not sufficiently
perform classloader consistency checks. An attacker could use this to
bypass Java sandbox restrictions. (CVE-2016-5554)

It was discovered that the Hotspot component of OpenJDK did not properly
check received Java Debug Wire Protocol (JDWP) packets. An attacker could
use this to send debugging commands to a Java application with debugging
enabled. (CVE-2016-5573)

It was discovered that the Hotspot component of OpenJDK did not properly
check arguments of the System.arraycopy() function in certain cases. An
attacker could use this to bypass Java sandbox restrictions.
(CVE-2016-5582)

It was discovered that OpenJDK did not properly handle HTTP proxy
authentication. An attacker could use this to expose HTTPS server
authentication credentials. (CVE-2016-5597)" );
	script_tag( name: "affected", value: "openjdk-7 on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3130-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3130-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm", ver: "7u121-2.6.8-1ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre", ver: "7u121-2.6.8-1ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless", ver: "7u121-2.6.8-1ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u121-2.6.8-1ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero", ver: "7u121-2.6.8-1ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

