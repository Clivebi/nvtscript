if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851291" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-05-06 15:29:28 +0530 (Fri, 06 May 2016)" );
	script_cve_id( "CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3427" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for java-1_7_0-openjdk (openSUSE-SU-2016:1235-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_0-openjdk to version 2.6.6 fixes five security
  issues.

  These security issues were fixed:

  - CVE-2016-0686: Ensure thread consistency (bsc#976340).

  - CVE-2016-0687: Better byte behavior (bsc#976340).

  - CVE-2016-0695: Make DSA more fair (bsc#976340).

  - CVE-2016-3425: Better buffering of XML strings (bsc#976340).

  - CVE-2016-3427: Improve JMX connections (bsc#976340)." );
	script_tag( name: "affected", value: "java-1_7_0-openjdk on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1235-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk", rpm: "java-1_7_0-openjdk~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-accessibility", rpm: "java-1_7_0-openjdk-accessibility~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debuginfo", rpm: "java-1_7_0-openjdk-debuginfo~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debugsource", rpm: "java-1_7_0-openjdk-debugsource~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo", rpm: "java-1_7_0-openjdk-demo~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo-debuginfo", rpm: "java-1_7_0-openjdk-demo-debuginfo~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel", rpm: "java-1_7_0-openjdk-devel~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel-debuginfo", rpm: "java-1_7_0-openjdk-devel-debuginfo~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless", rpm: "java-1_7_0-openjdk-headless~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless-debuginfo", rpm: "java-1_7_0-openjdk-headless-debuginfo~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-src", rpm: "java-1_7_0-openjdk-src~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-javadoc", rpm: "java-1_7_0-openjdk-javadoc~1.7.0.101~24.36.2", rls: "openSUSE13.1" ) )){
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

