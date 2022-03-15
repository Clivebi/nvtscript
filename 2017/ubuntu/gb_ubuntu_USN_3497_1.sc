if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843387" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-30 07:34:52 +0100 (Thu, 30 Nov 2017)" );
	script_cve_id( "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10357", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10388" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-7 USN-3497-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Smart Card IO
  subsystem in OpenJDK did not properly maintain state. An attacker could use this
  to specially construct an untrusted Java application or applet to gain access to
  a smart card, bypassing sandbox restrictions. (CVE-2017-10274) Gaston Traberg
  discovered that the Serialization component of OpenJDK did not properly limit
  the amount of memory allocated when performing deserializations. An attacker
  could use this to cause a denial of service (memory exhaustion).
  (CVE-2017-10281) It was discovered that the Remote Method Invocation (RMI)
  component in OpenJDK did not properly handle unreferenced objects. An attacker
  could use this to specially construct an untrusted Java application or applet
  that could escape sandbox restrictions. (CVE-2017-10285) It was discovered that
  the HTTPUrlConnection classes in OpenJDK did not properly handle newlines. An
  attacker could use this to convince a Java application or applet to inject
  headers into http requests. (CVE-2017-10295) Francesco Palmarini, Marco
  Squarcina, Mauro Tempesta, and Riccardo Focardi discovered that the
  Serialization component of OpenJDK did not properly restrict the amount of
  memory allocated when deserializing objects from Java Cryptography Extension
  KeyStore (JCEKS). An attacker could use this to cause a denial of service
  (memory exhaustion). (CVE-2017-10345) It was discovered that the Hotspot
  component of OpenJDK did not properly perform loader checks when handling the
  invokespecial JVM instruction. An attacker could use this to specially construct
  an untrusted Java application or applet that could escape sandbox restrictions.
  (CVE-2017-10346) Gaston Traberg discovered that the Serialization component of
  OpenJDK did not properly limit the amount of memory allocated when performing
  deserializations in the SimpleTimeZone class. An attacker could use this to
  cause a denial of service (memory exhaustion). (CVE-2017-10347) It was
  discovered that the Serialization component of OpenJDK did not properly limit
  the amount of memory allocated when performing deserializations. An attacker
  could use this to cause a denial of service (memory exhaustion).
  (CVE-2017-10348, CVE-2017-10357) It was discovered that the JAXP component in
  OpenJDK did not properly limit the amount of memory allocated when performing
  deserializations. An attacker could use this to cause a denial of service
  (memory exhaustion). (CVE-2017-10349) It was discovered that the JAX-WS
  component in OpenJDK did not properly limit the amount of memory allocated when
  performing deserializations. An attacker could use this to cause a denial ...
  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "openjdk-7 on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3497-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3497-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:amd64", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:i386", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:amd64", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:i386", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:amd64", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:i386", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:amd64", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:i386", ver: "7u151-2.6.11-2ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

