if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883175" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2020-2583", "CVE-2020-2590", "CVE-2020-2593", "CVE-2020-2601", "CVE-2020-2604", "CVE-2020-2654", "CVE-2020-2659" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 20:48:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-01-29 04:01:22 +0000 (Wed, 29 Jan 2020)" );
	script_name( "CentOS: Security Advisory for java (CESA-2020:0196)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:0196" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-January/035617.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2020:0196 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Use of unsafe RSA-MD5 checksum in Kerberos TGS (Security,
8229951) (CVE-2020-2601)

  * OpenJDK: Serialization filter changes via jdk.serialFilter property
modification (Serialization, 8231422) (CVE-2020-2604)

  * OpenJDK: Improper checks of SASL message properties in GssKrb5Base
(Security, 8226352) (CVE-2020-2590)

  * OpenJDK: Incorrect isBuiltinStreamHandler causing URL normalization
issues (Networking, 8228548) (CVE-2020-2593)

  * OpenJDK: Excessive memory usage in OID processing in X.509 certificate
parsing (Libraries, 8234037) (CVE-2020-2654)

  * OpenJDK: Incorrect exception processing during deserialization in
BeanContextSupport (Serialization, 8224909) (CVE-2020-2583)

  * OpenJDK: Incomplete enforcement of maxDatagramSockets limit in
DatagramChannelImpl (Networking, 8231795) (CVE-2020-2659)

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
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk", rpm: "java-1.8.0-openjdk~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-accessibility", rpm: "java-1.8.0-openjdk-accessibility~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-accessibility-debug", rpm: "java-1.8.0-openjdk-accessibility-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-debug", rpm: "java-1.8.0-openjdk-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo", rpm: "java-1.8.0-openjdk-demo~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo-debug", rpm: "java-1.8.0-openjdk-demo-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel", rpm: "java-1.8.0-openjdk-devel~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel-debug", rpm: "java-1.8.0-openjdk-devel-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless", rpm: "java-1.8.0-openjdk-headless~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless-debug", rpm: "java-1.8.0-openjdk-headless-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc", rpm: "java-1.8.0-openjdk-javadoc~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-debug", rpm: "java-1.8.0-openjdk-javadoc-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-zip", rpm: "java-1.8.0-openjdk-javadoc-zip~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-zip-debug", rpm: "java-1.8.0-openjdk-javadoc-zip-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src", rpm: "java-1.8.0-openjdk-src~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src-debug", rpm: "java-1.8.0-openjdk-src-debug~1.8.0.242.b08~0.el7_7", rls: "CentOS7" ) )){
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

