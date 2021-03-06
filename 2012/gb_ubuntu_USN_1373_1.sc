if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1373-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840909" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-09 18:57:39 +0530 (Fri, 09 Mar 2012)" );
	script_cve_id( "CVE-2011-5035", "CVE-2011-3563", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1373-1" );
	script_name( "Ubuntu Update for openjdk-6 USN-1373-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1373-1" );
	script_tag( name: "affected", value: "openjdk-6 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the Java HttpServer class did not limit the
  number of headers read from a HTTP request. A remote attacker could
  cause a denial of service by sending special requests that trigger
  hash collisions predictably. (CVE-2011-5035)

  ATTENTION: this update changes previous Java HttpServer class behavior
  by limiting the number of request headers to 200. This may be increased
  by adjusting the sun.net.httpserver.maxReqHeaders property.

  It was discovered that the Java Sound component did not properly
  check buffer boundaries. A remote attacker could use this to cause
  a denial of service or view confidential data. (CVE-2011-3563)

  It was discovered that the Java2D implementation does not properly
  check graphics rendering objects before passing them to the native
  renderer. A remote attacker could use this to cause a denial of
  service or to bypass Java sandbox restrictions. (CVE-2012-0497)

  It was discovered that an off-by-one error exists in the Java ZIP
  file processing code. An attacker could us this to cause a denial of
  service through a maliciously crafted ZIP file. (CVE-2012-0501)

  It was discovered that the Java AWT KeyboardFocusManager did not
  properly enforce keyboard focus security policy. A remote attacker
  could use this with an untrusted application or applet to grab keyboard
  focus and possibly expose confidential data. (CVE-2012-0502)

  It was discovered that the Java TimeZone class did not properly enforce
  security policy around setting the default time zone. A remote attacker
  could use this with an untrusted application or applet to set a new
  default time zone and bypass Java sandbox restrictions. (CVE-2012-0503)

  It was discovered the Java ObjectStreamClass did not throw
  an accurately identifiable exception when a deserialization
  failure occurred. A remote attacker could use this with
  an untrusted application or applet to bypass Java sandbox
  restrictions. (CVE-2012-0505)

  It was discovered that the Java CORBA implementation did not properly
  protect repository identifiers on certain CORBA objects. A remote
  attacker could use this to corrupt object data. (CVE-2012-0506)

  It was discovered that the Java AtomicReferenceArray class
  implementation did not properly check if an array was of
  the expected Object[] type. A remote attacker could use this
  with a malicious application or applet to bypass Java sandbox
  restrictions. (CVE-2012-0507)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b20-1.9.13-0ubuntu1~10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b20-1.9.13-0ubuntu1~10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b20-1.9.13-0ubuntu1~10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b20-1.9.13-0ubuntu1~10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b20-1.9.13-0ubuntu1~10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b20-1.9.13-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b20-1.9.13-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b20-1.9.13-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b20-1.9.13-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b20-1.9.13-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b22-1.10.6-0ubuntu1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b22-1.10.6-0ubuntu1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b22-1.10.6-0ubuntu1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b22-1.10.6-0ubuntu1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b22-1.10.6-0ubuntu1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b22-1.10.6-0ubuntu1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

