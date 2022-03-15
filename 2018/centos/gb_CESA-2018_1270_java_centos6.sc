if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882873" );
	script_version( "2021-05-21T08:07:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-21 08:07:35 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-03 05:30:13 +0200 (Thu, 03 May 2018)" );
	script_cve_id( "CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for java CESA-2018:1270 centos6" );
	script_tag( name: "summary", value: "Check the version of java" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.7.0-openjdk packages provide the
  OpenJDK 7 Java Runtime Environment and the OpenJDK 7 Java Software Development
  Kit.

Security Fix(es):

  * OpenJDK: incorrect handling of Reference clones can lead to sandbox
bypass (Hotspot, 8192025) (CVE-2018-2814)

  * OpenJDK: unrestricted deserialization of data from JCEKS key stores
(Security, 8189997) (CVE-2018-2794)

  * OpenJDK: insufficient consistency checks in deserialization of multiple
classes (Security, 8189977) (CVE-2018-2795)

  * OpenJDK: unbounded memory allocation during deserialization in
PriorityBlockingQueue (Concurrency, 8189981) (CVE-2018-2796)

  * OpenJDK: unbounded memory allocation during deserialization in
TabularDataSupport (JMX, 8189985) (CVE-2018-2797)

  * OpenJDK: unbounded memory allocation during deserialization in Container
(AWT, 8189989) (CVE-2018-2798)

  * OpenJDK: unbounded memory allocation during deserialization in
NamedNodeMapImpl (JAXP, 8189993) (CVE-2018-2799)

  * OpenJDK: RMI HTTP transport enabled by default (RMI, 8193833)
(CVE-2018-2800)

  * OpenJDK: unbounded memory allocation during deserialization in
StubIORImpl (Serialization, 8192757) (CVE-2018-2815)

  * OpenJDK: incorrect merging of sections in the JAR manifest (Security,
8189969) (CVE-2018-2790)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section." );
	script_tag( name: "affected", value: "java on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:1270" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-May/022816.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.181~2.6.14.1.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-demo", rpm: "java-1.7.0-openjdk-demo~1.7.0.181~2.6.14.1.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.181~2.6.14.1.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-javadoc", rpm: "java-1.7.0-openjdk-javadoc~1.7.0.181~2.6.14.1.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-src", rpm: "java-1.7.0-openjdk-src~1.7.0.181~2.6.14.1.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

