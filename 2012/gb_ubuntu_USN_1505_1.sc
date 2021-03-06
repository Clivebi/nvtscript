if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1505-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841080" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-16 11:53:18 +0530 (Mon, 16 Jul 2012)" );
	script_cve_id( "CVE-2012-1711", "CVE-2012-1719", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1723", "CVE-2012-1725", "CVE-2012-1724" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1505-1" );
	script_name( "Ubuntu Update for openjdk-6 USN-1505-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1505-1" );
	script_tag( name: "affected", value: "openjdk-6 on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that multiple flaws existed in the CORBA (Common
  Object Request Broker Architecture) implementation in OpenJDK. An
  attacker could create a Java application or applet that used these
  flaws to bypass Java sandbox restrictions or modify immutable object
  data. (CVE-2012-1711, CVE-2012-1719)

  It was discovered that multiple flaws existed in the OpenJDK font
  manager's layout lookup implementation. A attacker could specially
  craft a font file that could cause a denial of service through
  crashing the JVM (Java Virtual Machine) or possibly execute arbitrary
  code. (CVE-2012-1713)

  It was discovered that the SynthLookAndFeel class from Swing in
  OpenJDK did not properly prevent access to certain UI elements
  from outside the current application context. An attacker could
  create a Java application or applet that used this flaw to cause a
  denial of service through crashing the JVM or bypass Java sandbox
  restrictions. (CVE-2012-1716)

  It was discovered that OpenJDK runtime library classes could create
  temporary files with insecure permissions. A local attacker could
  use this to gain access to sensitive information. (CVE-2012-1717)

  It was discovered that OpenJDK did not handle CRLs (Certificate
  Revocation Lists) properly. A remote attacker could use this to gain
  access to sensitive information. (CVE-2012-1718)

  It was discovered that the OpenJDK HotSpot Virtual Machine did not
  properly verify the bytecode of the class to be executed. A remote
  attacker could create a Java application or applet that used this
  to cause a denial of service through crashing the JVM or bypass Java
  sandbox restrictions. (CVE-2012-1723, CVE-2012-1725)

  It was discovered that the OpenJDK XML (Extensible Markup Language)
  parser did not properly handle some XML documents. An attacker could
  create an XML document that caused a denial of service in a Java
  application or applet parsing the document. (CVE-2012-1724)

  As part of this update, the IcedTea web browser applet plugin was
  updated for Ubuntu 10.04 LTS, Ubuntu 11.04, and Ubuntu 11.10." );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2-2ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b24-1.11.3-1ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b24-1.11.3-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2-2ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b24-1.11.3-1ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-plugin", ver: "1.2-2ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b24-1.11.3-1ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

