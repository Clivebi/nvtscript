if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882754" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-22 07:21:17 +0200 (Sat, 22 Jul 2017)" );
	script_cve_id( "CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10193", "CVE-2017-10198" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for java CESA-2017:1789 centos6" );
	script_tag( name: "summary", value: "Check the version of java" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.8.0-openjdk packages provide
the OpenJDK 8 Java Runtime Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * It was discovered that the DCG implementation in the RMI component of
OpenJDK failed to correctly handle references. A remote attacker could
possibly use this flaw to execute arbitrary code with the privileges of RMI
registry or a Java RMI application. (CVE-2017-10102)

  * Multiple flaws were discovered in the RMI, JAXP, ImageIO, Libraries, AWT,
Hotspot, and Security components in OpenJDK. An untrusted Java application
or applet could use these flaws to completely bypass Java sandbox
restrictions. (CVE-2017-10107, CVE-2017-10096, CVE-2017-10101,
CVE-2017-10089, CVE-2017-10090, CVE-2017-10087, CVE-2017-10111,
CVE-2017-10110, CVE-2017-10074, CVE-2017-10067)

  * It was discovered that the LDAPCertStore class in the Security component
of OpenJDK followed LDAP referrals to arbitrary URLs. A specially crafted
LDAP referral URL could cause LDAPCertStore to communicate with non-LDAP
servers. (CVE-2017-10116)

  * It was discovered that the Nashorn JavaScript engine in the Scripting
component of OpenJDK could allow scripts to access Java APIs even when
access to Java APIs was disabled. An untrusted JavaScript executed by
Nashorn could use this flaw to bypass intended restrictions.
(CVE-2017-10078)

  * It was discovered that the Security component of OpenJDK could fail to
properly enforce restrictions defined for processing of X.509 certificate
chains. A remote attacker could possibly use this flaw to make Java accept
certificate using one of the disabled algorithms. (CVE-2017-10198)

  * A covert timing channel flaw was found in the DSA implementation in the
JCE component of OpenJDK. A remote attacker able to make a Java application
generate DSA signatures on demand could possibly use this flaw to extract
certain information about the used key via a timing side channel.
(CVE-2017-10115)

  * A covert timing channel flaw was found in the PKCS#8 implementation in
the JCE component of OpenJDK. A remote attacker able to make a Java
application repeatedly compare PKCS#8 key against an attacker controlled
value could possibly use this flaw to determine the key via a timing side
channel. (CVE-2017-10135)

  * It was discovered that the BasicAttribute and CodeSource classes in
OpenJDK did not limit the amount of memory allocated when creating object
instances from a serialized form. A specially crafted serialized input
stream could cause Java to consume an excessive amount of memory.
(CVE-2017-10108, CVE-2017-10109)

  * Multiple flaws were found in the Hotspot and Security compone ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "java on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:1789" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-July/022508.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk", rpm: "java-1.8.0-openjdk~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-debug", rpm: "java-1.8.0-openjdk-debug~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo", rpm: "java-1.8.0-openjdk-demo~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo-debug", rpm: "java-1.8.0-openjdk-demo-debug~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel", rpm: "java-1.8.0-openjdk-devel~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel-debug", rpm: "java-1.8.0-openjdk-devel-debug~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless", rpm: "java-1.8.0-openjdk-headless~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless-debug", rpm: "java-1.8.0-openjdk-headless-debug~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc", rpm: "java-1.8.0-openjdk-javadoc~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-debug", rpm: "java-1.8.0-openjdk-javadoc-debug~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src", rpm: "java-1.8.0-openjdk-src~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src-debug", rpm: "java-1.8.0-openjdk-src-debug~1.8.0.141~2.b16.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

