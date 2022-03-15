if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882640" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-22 05:39:57 +0100 (Sun, 22 Jan 2017)" );
	script_cve_id( "CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289", "CVE-2016-2183" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-10 19:29:00 +0000 (Mon, 10 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for java CESA-2017:0180 centos6" );
	script_tag( name: "summary", value: "Check the version of java" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.8.0-openjdk packages provide the
OpenJDK 8 Java Runtime Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * It was discovered that the RMI registry and DCG implementations in the
RMI component of OpenJDK performed deserialization of untrusted inputs. A
remote attacker could possibly use this flaw to execute arbitrary code with
the privileges of RMI registry or a Java RMI application. (CVE-2017-3241)

This issue was addressed by introducing whitelists of classes that can be
deserialized by RMI registry or DCG. These whitelists can be customized
using the newly introduced sun.rmi.registry.registryFilter and
sun.rmi.transport.dgcFilter security properties.

  * Multiple flaws were discovered in the Libraries and Hotspot components in
OpenJDK. An untrusted Java application or applet could use these flaws to
completely bypass Java sandbox restrictions. (CVE-2017-3272, CVE-2017-3289)

  * A covert timing channel flaw was found in the DSA implementation in the
Libraries component of OpenJDK. A remote attacker could possibly use this
flaw to extract certain information about the used key via a timing side
channel. (CVE-2016-5548)

  * It was discovered that the Libraries component of OpenJDK accepted ECSDA
signatures using non-canonical DER encoding. This could cause a Java
application to accept signature in an incorrect format not accepted by
other cryptographic tools. (CVE-2016-5546)

  * It was discovered that the 2D component of OpenJDK performed parsing of
iTXt and zTXt PNG image chunks even when configured to ignore metadata. An
attacker able to make a Java application parse a specially crafted PNG
image could cause the application to consume an excessive amount of memory.
(CVE-2017-3253)

  * It was discovered that the Libraries component of OpenJDK did not
validate the length of the object identifier read from the DER input before
allocating memory to store the OID. An attacker able to make a Java
application decode a specially crafted DER input could cause the
application to consume an excessive amount of memory. (CVE-2016-5547)

  * It was discovered that the JAAS component of OpenJDK did not use the
correct way to extract user DN from the result of the user search LDAP
query. A specially crafted user LDAP entry could cause the application to
use an incorrect DN. (CVE-2017-3252)

  * It was discovered that the Networking component of OpenJDK failed to
properly parse user info from the URL. A remote attacker could cause a Java
application to incorrectly parse an attacker supplied URL and interpret it
differently from other applications processing the same URL.
(CVE-2016- ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "java on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:0180" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-January/022247.html" );
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
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk", rpm: "java-1.8.0-openjdk~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-debug", rpm: "java-1.8.0-openjdk-debug~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo", rpm: "java-1.8.0-openjdk-demo~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo-debug", rpm: "java-1.8.0-openjdk-demo-debug~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel", rpm: "java-1.8.0-openjdk-devel~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel-debug", rpm: "java-1.8.0-openjdk-devel-debug~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless", rpm: "java-1.8.0-openjdk-headless~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless-debug", rpm: "java-1.8.0-openjdk-headless-debug~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc", rpm: "java-1.8.0-openjdk-javadoc~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-debug", rpm: "java-1.8.0-openjdk-javadoc-debug~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src", rpm: "java-1.8.0-openjdk-src~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src-debug", rpm: "java-1.8.0-openjdk-src-debug~1.8.0.121~0.b13.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

