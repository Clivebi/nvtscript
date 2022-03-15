if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851384" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-08-13 05:53:05 +0200 (Sat, 13 Aug 2016)" );
	script_cve_id( "CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3498", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3511", "CVE-2016-3550", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for OpenJDK7 (openSUSE-SU-2016:2058-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OpenJDK7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Update to 2.6.7 - OpenJDK 7u111

  * Security fixes

  - S8079718, CVE-2016-3458: IIOP Input Stream Hooking (bsc#989732)

  - S8145446, CVE-2016-3485: Perfect pipe placement (Windows
  only)  (bsc#989734)

  - S8147771: Construction of static protection domains under Javax
  custom policy

  - S8148872, CVE-2016-3500: Complete name checking (bsc#989730)

  - S8149962, CVE-2016-3508: Better delineation of XML processing
  (bsc#989731)

  - S8150752: Share Class Data

  - S8151925: Font reference improvements

  - S8152479, CVE-2016-3550: Coded byte streams (bsc#989733)

  - S8155981, CVE-2016-3606: Bolster bytecode verification (bsc#989722)

  - S8155985, CVE-2016-3598: Persistent Parameter Processing (bsc#989723)

  - S8158571, CVE-2016-3610: Additional method handle validation
  (bsc#989725)

  - CVE-2016-3511 (bsc#989727)

  - CVE-2016-3503 (bsc#989728)

  - CVE-2016-3498 (bsc#989729)" );
	script_tag( name: "affected", value: "OpenJDK7 on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:2058-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk", rpm: "java-1_7_0-openjdk~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-accessibility", rpm: "java-1_7_0-openjdk-accessibility~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debuginfo", rpm: "java-1_7_0-openjdk-debuginfo~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debugsource", rpm: "java-1_7_0-openjdk-debugsource~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo", rpm: "java-1_7_0-openjdk-demo~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo-debuginfo", rpm: "java-1_7_0-openjdk-demo-debuginfo~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel", rpm: "java-1_7_0-openjdk-devel~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel-debuginfo", rpm: "java-1_7_0-openjdk-devel-debuginfo~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless", rpm: "java-1_7_0-openjdk-headless~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless-debuginfo", rpm: "java-1_7_0-openjdk-headless-debuginfo~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-src", rpm: "java-1_7_0-openjdk-src~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-javadoc", rpm: "java-1_7_0-openjdk-javadoc~1.7.0.111~24.39.1", rls: "openSUSE13.1" ) )){
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

