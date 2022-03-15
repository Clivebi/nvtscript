if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882237" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-10 12:58:28 +0530 (Mon, 10 Aug 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for java CESA-2015:1526 centos7" );
	script_tag( name: "summary", value: "Check the version of java" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Multiple flaws were discovered in the 2D, CORBA, JMX, Libraries and RMI
components in OpenJDK. An untrusted Java application or applet could use
these flaws to bypass Java sandbox restrictions. (CVE-2015-4760,
CVE-2015-2628, CVE-2015-4731, CVE-2015-2590, CVE-2015-4732, CVE-2015-4733)

A flaw was found in the way the Libraries component of OpenJDK verified
Online Certificate Status Protocol (OCSP) responses. An OCSP response with
no nextUpdate date specified was incorrectly handled as having unlimited
validity, possibly causing a revoked X.509 certificate to be interpreted as
valid. (CVE-2015-4748)

It was discovered that the JCE component in OpenJDK failed to use constant
time comparisons in multiple cases. An attacker could possibly use these
flaws to disclose sensitive information by measuring the time used to
perform operations using these non-constant time comparisons.
(CVE-2015-2601)

A flaw was found in the RC4 encryption algorithm. When using certain keys
for RC4 encryption, an attacker could obtain portions of the plain text
from the cipher text without the knowledge of the encryption key.
(CVE-2015-2808)

Note: With this update, OpenJDK now disables RC4 TLS/SSL cipher suites by
default to address the CVE-2015-2808 issue. Refer to Red Hat Bugzilla bug
1207101, linked to in the References section, for additional details about
this change.

A flaw was found in the way the TLS protocol composed the Diffie-Hellman
(DH) key exchange. A man-in-the-middle attacker could use this flaw to
force the use of weak 512 bit export-grade keys during the key exchange,
allowing them to decrypt all traffic. (CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in OpenJDK to
reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Refer to Red Hat Bugzilla bug 1223211,
linked to in the References section, for additional details about this
change.

It was discovered that the JNDI component in OpenJDK did not handle DNS
resolutions correctly. An attacker able to trigger such DNS errors could
cause a Java application using JNDI to consume memory and CPU time, and
possibly block further DNS resolution. (CVE-2015-4749)

Multiple information leak flaws were found in the JMX and 2D components in
OpenJDK. An untrusted Java application or applet could use this flaw to
bypass certain Java sandbox restrictions. (CVE-2015-2621, CVE-2015-2632)

A flaw was found in the way the JSSE component in OpenJDK performed X.509
certificate ident ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "java on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1526" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-July/021271.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.36~1.13.8.1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-demo", rpm: "java-1.6.0-openjdk-demo~1.6.0.36~1.13.8.1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-devel", rpm: "java-1.6.0-openjdk-devel~1.6.0.36~1.13.8.1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-javadoc", rpm: "java-1.6.0-openjdk-javadoc~1.6.0.36~1.13.8.1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-src", rpm: "java-1.6.0-openjdk-src~1.6.0.36~1.13.8.1.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

