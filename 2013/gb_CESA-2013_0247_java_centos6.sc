if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-February/019234.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881596" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-11 10:20:58 +0530 (Mon, 11 Feb 2013)" );
	script_cve_id( "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0431", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0444", "CVE-2013-0445", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2013:0247" );
	script_name( "CentOS Update for java CESA-2013:0247 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "java on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "These packages provide the OpenJDK 7 Java Runtime Environment and the
  OpenJDK 7 Software Development Kit.

  Multiple improper permission check issues were discovered in the AWT,
  CORBA, JMX, Libraries, and Beans components in OpenJDK. An untrusted Java
  application or applet could use these flaws to bypass Java sandbox
  restrictions. (CVE-2013-0442, CVE-2013-0445, CVE-2013-0441, CVE-2013-1475,
  CVE-2013-1476, CVE-2013-0429, CVE-2013-0450, CVE-2013-0425, CVE-2013-0426,
  CVE-2013-0428, CVE-2013-0444)

  Multiple flaws were found in the way image parsers in the 2D and AWT
  components handled image raster parameters. A specially-crafted image could
  cause Java Virtual Machine memory corruption and, possibly, lead to
  arbitrary code execution with the virtual machine privileges.
  (CVE-2013-1478, CVE-2013-1480)

  A flaw was found in the AWT component's clipboard handling code. An
  untrusted Java application or applet could use this flaw to access
  clipboard data, bypassing Java sandbox restrictions. (CVE-2013-0432)

  The default Java security properties configuration did not restrict access
  to certain com.sun.xml.internal packages. An untrusted Java application or
  applet could use this flaw to access information, bypassing certain Java
  sandbox restrictions. This update lists the whole package as restricted.
  (CVE-2013-0435)

  Multiple improper permission check issues were discovered in the JMX,
  Libraries, Networking, and JAXP components. An untrusted Java application
  or applet could use these flaws to bypass certain Java sandbox
  restrictions. (CVE-2013-0431, CVE-2013-0427, CVE-2013-0433, CVE-2013-0434)

  It was discovered that the RMI component's CGIHandler class used user
  inputs in error messages without any sanitization. An attacker could use
  this flaw to perform a cross-site scripting (XSS) attack. (CVE-2013-0424)

  It was discovered that the SSL/TLS implementation in the JSSE component
  did not properly enforce handshake message ordering, allowing an unlimited
  number of handshake restarts. A remote attacker could use this flaw to
  make an SSL/TLS server using JSSE consume an excessive amount of CPU by
  continuously restarting the handshake. (CVE-2013-0440)

  It was discovered that the JSSE component did not properly validate
  Diffie-Hellman public keys. An SSL/TLS client could possibly use this flaw
  to perform a small subgroup attack. (CVE-2013-0443)

  This erratum also upgrades the OpenJDK package to IcedTea7 2.3.5. Refer to
  the NEWS file, linked to in the References, for further information.

  All users of java-1.7.0-openjdk are advised to upgrade to these updated
  packages, which resolve these issues. All running instances of OpenJDK Java
  must be restarted for the update to take effect." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.9~2.3.5.3.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-demo", rpm: "java-1.7.0-openjdk-demo~1.7.0.9~2.3.5.3.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.9~2.3.5.3.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-javadoc", rpm: "java-1.7.0-openjdk-javadoc~1.7.0.9~2.3.5.3.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-src", rpm: "java-1.7.0-openjdk-src~1.7.0.9~2.3.5.3.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

