if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882983" );
	script_version( "2021-05-21T08:07:35+0000" );
	script_cve_id( "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3150", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-21 08:07:35 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-12-18 07:38:15 +0100 (Tue, 18 Dec 2018)" );
	script_name( "CentOS Update for java-11-openjdk CESA-2018:3521 centos7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2018:3521" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-December/023105.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the CESA-2018:3521 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The java-11-openjdk packages provide the OpenJDK 11 Java Runtime
Environment and the OpenJDK 11 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Improper field access checks (Hotspot, 8199226) (CVE-2018-3169)

  * OpenJDK: Unrestricted access to scripting engine (Scripting, 8202936)
(CVE-2018-3183)

  * OpenJDK: Incomplete enforcement of the trustURLCodebase restriction
(JNDI, 8199177) (CVE-2018-3149)

  * OpenJDK: Incorrect handling of unsigned attributes in signed Jar
manifests (Security, 8194534) (CVE-2018-3136)

  * OpenJDK: Leak of sensitive header data via HTTP redirect (Networking,
8196902) (CVE-2018-3139)

  * OpenJDK: Multi-Release attribute read from outside of the main manifest
attributes (Utility, 8199171) (CVE-2018-3150)

  * OpenJDK: Missing endpoint identification algorithm check during TLS
session resumption (JSSE, 8202613) (CVE-2018-3180)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section." );
	script_tag( name: "affected", value: "java-11-openjdk on CentOS 7." );
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
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "java-11-openjdk", rpm: "java-11-openjdk~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-debug", rpm: "java-11-openjdk-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-demo", rpm: "java-11-openjdk-demo~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-demo-debug", rpm: "java-11-openjdk-demo-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-devel", rpm: "java-11-openjdk-devel~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-devel-debug", rpm: "java-11-openjdk-devel-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-headless", rpm: "java-11-openjdk-headless~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-headless-debug", rpm: "java-11-openjdk-headless-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-javadoc", rpm: "java-11-openjdk-javadoc~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-javadoc-debug", rpm: "java-11-openjdk-javadoc-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-javadoc-zip", rpm: "java-11-openjdk-javadoc-zip~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-javadoc-zip-debug", rpm: "java-11-openjdk-javadoc-zip-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-jmods", rpm: "java-11-openjdk-jmods~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-jmods-debug", rpm: "java-11-openjdk-jmods-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-src", rpm: "java-11-openjdk-src~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-11-openjdk-src-debug", rpm: "java-11-openjdk-src-debug~11.0.1.13~3.el7_6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

