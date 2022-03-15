if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883266" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2020-14556", "CVE-2020-14577", "CVE-2020-14578", "CVE-2020-14579", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-08 03:00:37 +0000 (Sat, 08 Aug 2020)" );
	script_name( "CentOS: Security Advisory for java (CESA-2020:2968)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:2968" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-August/035792.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2020:2968 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Bypass of boundary checks in nio.Buffer via concurrent access
(Libraries, 8238920) (CVE-2020-14583)

  * OpenJDK: Incomplete bounds checks in Affine Transformations (2D, 8240119)
(CVE-2020-14593)

  * OpenJDK: Incorrect handling of access control context in ForkJoinPool
(Libraries, 8237117) (CVE-2020-14556)

  * OpenJDK: Unexpected exception raised by DerInputStream (Libraries,
8237731) (CVE-2020-14578)

  * OpenJDK: Unexpected exception raised by DerValue.equals() (Libraries,
8237736) (CVE-2020-14579)

  * OpenJDK: XML validation manipulation due to incomplete application of the
use-grammar-pool-only feature (JAXP, 8242136) (CVE-2020-14621)

  * OpenJDK: HostnameChecker does not ensure X.509 certificate names are in
normalized form (JSSE, 8237592) (CVE-2020-14577)

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
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk", rpm: "java-1.8.0-openjdk~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-accessibility", rpm: "java-1.8.0-openjdk-accessibility~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo", rpm: "java-1.8.0-openjdk-demo~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel", rpm: "java-1.8.0-openjdk-devel~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless", rpm: "java-1.8.0-openjdk-headless~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc", rpm: "java-1.8.0-openjdk-javadoc~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-zip", rpm: "java-1.8.0-openjdk-javadoc-zip~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src", rpm: "java-1.8.0-openjdk-src~1.8.0.262.b10~0.el7_8", rls: "CentOS7" ) )){
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

