if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882325" );
	script_version( "2021-04-21T15:24:38+0000" );
	script_cve_id( "CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-21 15:24:38 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-21 14:10:46 +0000 (Wed, 21 Apr 2021)" );
	script_name( "CentOS: Security Advisory for java (CESA-2015:2086)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_xref( name: "Advisory-ID", value: "CESA-2015:2086" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2015-November/021506.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2015:2086 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The java-1.6.0-openjdk packages provide the
OpenJDK 6 Java Runtime Environment and the OpenJDK 6 Java Software Development Kit.

Multiple flaws were discovered in the CORBA, Libraries, RMI, Serialization,
and 2D components in OpenJDK. An untrusted Java application or applet could
use these flaws to completely bypass Java sandbox restrictions.
(CVE-2015-4835, CVE-2015-4881, CVE-2015-4843, CVE-2015-4883, CVE-2015-4860,
CVE-2015-4805, CVE-2015-4844)

Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application using
JAXP to consume an excessive amount of CPU and memory when parsed.
(CVE-2015-4803, CVE-2015-4893, CVE-2015-4911)

It was discovered that the Security component in OpenJDK failed to properly
check if a certificate satisfied all defined constraints. In certain cases,
this could cause a Java application to accept an X.509 certificate which
does not meet requirements of the defined policy. (CVE-2015-4872)

Multiple flaws were found in the Libraries, CORBA, JAXP, JGSS, and RMI
components in OpenJDK. An untrusted Java application or applet could use
these flaws to bypass certain Java sandbox restrictions. (CVE-2015-4806,
CVE-2015-4882, CVE-2015-4842, CVE-2015-4734, CVE-2015-4903)

Red Hat would like to thank Andrea Palazzo of Truel IT for reporting the
CVE-2015-4806 issue.

All users of java-1.6.0-openjdk are advised to upgrade to these updated
packages, which resolve these issues. All running instances of OpenJDK Java
must be restarted for the update to take effect." );
	script_tag( name: "affected", value: "'java' package(s) on CentOS 5." );
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
if(release == "CentOS5"){
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.37~1.13.9.4.el5_11", rls: "CentOS5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-demo", rpm: "java-1.6.0-openjdk-demo~1.6.0.37~1.13.9.4.el5_11", rls: "CentOS5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-devel", rpm: "java-1.6.0-openjdk-devel~1.6.0.37~1.13.9.4.el5_11", rls: "CentOS5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-javadoc", rpm: "java-1.6.0-openjdk-javadoc~1.6.0.37~1.13.9.4.el5_11", rls: "CentOS5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-src", rpm: "java-1.6.0-openjdk-src~1.6.0.37~1.13.9.4.el5_11", rls: "CentOS5" ) )){
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

