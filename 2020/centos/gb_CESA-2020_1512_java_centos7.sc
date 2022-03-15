if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883230" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2773", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2830" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-05-01 03:01:24 +0000 (Fri, 01 May 2020)" );
	script_name( "CentOS: Security Advisory for java (CESA-2020:1512)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:1512" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-April/035706.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2020:1512 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Incorrect bounds checks in NIO Buffers (Libraries, 8234841)
(CVE-2020-2803)

  * OpenJDK: Incorrect type checks in MethodType.readObject() (Libraries,
8235274) (CVE-2020-2805)

  * OpenJDK: Unexpected exceptions raised by DOMKeyInfoFactory and
DOMXMLSignatureFactory (Security, 8231415) (CVE-2020-2773)

  * OpenJDK: Re-use of single TLS session for new connections (JSSE, 8234408)
(CVE-2020-2781)

  * OpenJDK: CRLF injection into HTTP headers in HttpServer (Lightweight HTTP
Server, 8234825) (CVE-2020-2800)

  * OpenJDK: Regular expression DoS in Scanner (Concurrency, 8236201)
(CVE-2020-2830)

  * OpenJDK: Misplaced regular expression syntax error check in RegExpScanner
(Scripting, 8223898) (CVE-2020-2754)

  * OpenJDK: Incorrect handling of empty string nodes in regular expression
Parser (Scripting, 8223904) (CVE-2020-2755)

  * OpenJDK: Incorrect handling of references to uninitialized class
descriptors during deserialization (Serialization, 8224541) (CVE-2020-2756)

  * OpenJDK: Uncaught InstantiationError exception in ObjectStreamClass
(Serialization, 8224549) (CVE-2020-2757)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'java' package(s) on CentOS 7." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk", rpm: "java-1.8.0-openjdk~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-accessibility", rpm: "java-1.8.0-openjdk-accessibility~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo", rpm: "java-1.8.0-openjdk-demo~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel", rpm: "java-1.8.0-openjdk-devel~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless", rpm: "java-1.8.0-openjdk-headless~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc", rpm: "java-1.8.0-openjdk-javadoc~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-zip", rpm: "java-1.8.0-openjdk-javadoc-zip~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src", rpm: "java-1.8.0-openjdk-src~1.8.0.252.b09~2.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

