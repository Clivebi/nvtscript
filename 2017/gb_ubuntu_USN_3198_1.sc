if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843052" );
	script_version( "2021-09-08T13:27:07+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:27:07 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-16 05:01:05 +0100 (Thu, 16 Feb 2017)" );
	script_cve_id( "CVE-2016-2183", "CVE-2016-5546", "CVE-2016-5548", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3261", "CVE-2017-3272" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-10 19:29:00 +0000 (Mon, 10 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-6 USN-3198-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-6'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Karthik Bhargavan and Gaetan Leurent
  discovered that the DES and Triple DES ciphers were vulnerable to birthday
  attacks. A remote attacker could possibly use this flaw to obtain clear text
  data from long encrypted sessions. This update moves those algorithms to the
legacy algorithm set and causes them to be used only if no non-legacy
algorithms can be negotiated. (CVE-2016-2183)

It was discovered that OpenJDK accepted ECSDA signatures using
non-canonical DER encoding. An attacker could use this to modify or
expose sensitive data. (CVE-2016-5546)

It was discovered that covert timing channel vulnerabilities existed
in the DSA implementations in OpenJDK. A remote attacker could use
this to expose sensitive information. (CVE-2016-5548)

It was discovered that the URLStreamHandler class in OpenJDK did not
properly parse user information from a URL. A remote attacker could
use this to expose sensitive information. (CVE-2016-5552)

It was discovered that the URLClassLoader class in OpenJDK did not
properly check access control context when downloading class files. A
remote attacker could use this to expose sensitive information.
(CVE-2017-3231)

It was discovered that the Remote Method Invocation (RMI)
implementation in OpenJDK performed deserialization of untrusted
inputs. A remote attacker could use this to execute arbitrary
code. (CVE-2017-3241)

It was discovered that the Java Authentication and Authorization
Service (JAAS) component of OpenJDK did not properly perform user
search LDAP queries. An attacker could use a specially constructed
LDAP entry to expose or modify sensitive information. (CVE-2017-3252)

It was discovered that the PNGImageReader class in OpenJDK did not
properly handle iTXt and zTXt chunks. An attacker could use this to
cause a denial of service (memory consumption). (CVE-2017-3253)

It was discovered that integer overflows existed in the
SocketInputStream and SocketOutputStream classes of OpenJDK. An
attacker could use this to expose sensitive information.
(CVE-2017-3261)

It was discovered that the atomic field updaters in the
java.util.concurrent.atomic package in OpenJDK did not properly
restrict access to protected field members. An attacker could use
this to specially craft a Java application or applet that could bypass
Java sandbox restrictions. (CVE-2017-3272)" );
	script_tag( name: "affected", value: "openjdk-6 on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3198-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3198-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao:i386", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao:amd64", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm:i386", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm:amd64", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jdk:i386", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jdk:amd64", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre:i386", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre:amd64", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless:i386", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless:amd64", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero:i386", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero:amd64", ver: "6b41-1.13.13-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

