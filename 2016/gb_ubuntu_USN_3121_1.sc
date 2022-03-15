if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842941" );
	script_version( "2021-09-20T11:27:24+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:27:24 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-04 05:44:17 +0100 (Fri, 04 Nov 2016)" );
	script_cve_id( "CVE-2016-5582", "CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5597" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-8 USN-3121-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Hotspot component
  of OpenJDK did not properly check arguments of the System.arraycopy() function
  in certain cases. An attacker could use this to bypass Java sandbox restrictions.
  (CVE-2016-5582)

It was discovered that OpenJDK did not restrict the set of algorithms used
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

It was discovered that OpenJDK did not properly handle HTTP proxy
authentication. An attacker could use this to expose HTTPS server
authentication credentials. (CVE-2016-5597)" );
	script_tag( name: "affected", value: "openjdk-8 on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3121-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3121-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(16\\.04 LTS|16\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:i386", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:amd64", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:i386", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:amd64", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:i386", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:amd64", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:i386", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:amd64", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:i386", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:amd64", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:i386", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:amd64", ver: "8u111-b14-2ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:i386", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:amd64", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:i386", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:amd64", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:i386", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:amd64", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:i386", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:amd64", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:i386", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:amd64", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:i386", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:amd64", ver: "8u111-b14-2ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

