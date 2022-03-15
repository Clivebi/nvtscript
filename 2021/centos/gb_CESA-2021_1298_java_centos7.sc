if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883344" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2021-2163" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:53:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-01 03:00:59 +0000 (Sat, 01 May 2021)" );
	script_name( "CentOS: Security Advisory for java (CESA-2021:1298)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:1298" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-April/048305.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2021:1298 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Incomplete enforcement of JAR signing disabled algorithms
(8249906) (CVE-2021-2163)

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
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk", rpm: "java-1.8.0-openjdk~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-accessibility", rpm: "java-1.8.0-openjdk-accessibility~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-demo", rpm: "java-1.8.0-openjdk-demo~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-devel", rpm: "java-1.8.0-openjdk-devel~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-headless", rpm: "java-1.8.0-openjdk-headless~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc", rpm: "java-1.8.0-openjdk-javadoc~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-javadoc-zip", rpm: "java-1.8.0-openjdk-javadoc-zip~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-src", rpm: "java-1.8.0-openjdk-src~1.8.0.292.b10~1.el7_9", rls: "CentOS7" ) )){
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

