if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853967" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-2163", "CVE-2021-2161" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:51:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:07:19 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for java-1_8_0-openj9 (openSUSE-SU-2021:1666-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1666-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CMIXIE2QCSQNEBZOFYWWIWYINHYQA6A5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-openj9'
  package(s) announced via the openSUSE-SU-2021:1666-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_8_0-openj9 fixes the following issues:

  - Update to OpenJDK 8u292 build 10 with OpenJ9 0.26.0 virtual machine.

  - CVE-2021-2161: Fixed incomplete enforcement of JAR signing disabled
       algorithms (bsc#1185055)." );
	script_tag( name: "affected", value: "'java-1_8_0-openj9' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9", rpm: "java-1_8_0-openj9~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-accessibility", rpm: "java-1_8_0-openj9-accessibility~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-debuginfo", rpm: "java-1_8_0-openj9-debuginfo~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-debugsource", rpm: "java-1_8_0-openj9-debugsource~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-demo", rpm: "java-1_8_0-openj9-demo~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-demo-debuginfo", rpm: "java-1_8_0-openj9-demo-debuginfo~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-devel", rpm: "java-1_8_0-openj9-devel~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-headless", rpm: "java-1_8_0-openj9-headless~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-src", rpm: "java-1_8_0-openj9-src~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-javadoc", rpm: "java-1_8_0-openj9-javadoc~1.8.0.292~3.14.1", rls: "openSUSELeap15.3" ) )){
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
