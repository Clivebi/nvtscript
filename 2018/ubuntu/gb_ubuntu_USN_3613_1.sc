if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843490" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-03 08:50:20 +0200 (Tue, 03 Apr 2018)" );
	script_cve_id( "CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-8 USN-3613-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that a race condition
  existed in the cryptography implementation in OpenJDK. An attacker could
  possibly use this to expose sensitive information. (CVE-2018-2579) It was
  discovered that the Hotspot component of OpenJDK did not properly validate uses
  of the invokeinterface JVM instruction. An attacker could possibly use this to
  access unauthorized resources. (CVE-2018-2582) It was discovered that the LDAP
  implementation in OpenJDK did not properly encode login names. A remote attacker
  could possibly use this to expose sensitive information. (CVE-2018-2588) It was
  discovered that the DNS client implementation in OpenJDK did not properly
  randomize source ports. A remote attacker could use this to spoof responses to
  DNS queries made by Java applications. (CVE-2018-2599) It was discovered that
  the Internationalization component of OpenJDK did not restrict search paths when
  loading resource bundle classes. A local attacker could use this to trick a user
  into running malicious code. (CVE-2018-2602) It was discovered that OpenJDK did
  not properly restrict memory allocations when parsing DER input. A remote
  attacker could possibly use this to cause a denial of service. (CVE-2018-2603)
  It was discovered that the Java Cryptography Extension (JCE) implementation in
  OpenJDK in some situations did guarantee sufficient strength of keys during key
  agreement. An attacker could use this to expose sensitive information.
  (CVE-2018-2618) It was discovered that the Java GSS implementation in OpenJDK in
  some situations did not properly handle GSS contexts in the native GSS library.
  An attacker could possibly use this to access unauthorized resources.
  (CVE-2018-2629) It was discovered that the LDAP implementation in OpenJDK did
  not properly handle LDAP referrals in some situations. An attacker could
  possibly use this to expose sensitive information or gain unauthorized
  privileges. (CVE-2018-2633) It was discovered that the Java GSS implementation
  in OpenJDK in some situations did not properly apply subject credentials. An
  attacker could possibly use this to expose sensitive information or gain access
  to unauthorized resources. (CVE-2018-2634) It was discovered that the Java
  Management Extensions (JMX) component of OpenJDK did not properly apply
  deserialization filters in some situations. An attacker could use this to bypass
  deserialization restrictions. (CVE-2018-2637) It was discovered that a
  use-after-free vulnerability existed in the AWT component of OpenJDK when
  loading the GTK library. An attacker could possibly use this to execute
  arbitrary code and escape Jav ... Description truncated, for more information
  please check the Reference URL" );
	script_tag( name: "affected", value: "openjdk-8 on Ubuntu 17.10,
  Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3613-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3613-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.10|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:amd64", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:i386", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:amd64", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:i386", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:amd64", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:i386", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:amd64", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:i386", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:amd64", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:i386", ver: "8u162-b12-0ubuntu0.17.10.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:amd64", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk:i386", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:amd64", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless:i386", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:amd64", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre:i386", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:amd64", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless:i386", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:amd64", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm:i386", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:amd64", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero:i386", ver: "8u162-b12-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

