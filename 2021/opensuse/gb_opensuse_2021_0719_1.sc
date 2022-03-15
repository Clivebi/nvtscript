if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853810" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-2161", "CVE-2021-2163" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:51:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-14 03:04:42 +0000 (Fri, 14 May 2021)" );
	script_name( "openSUSE: Security Advisory for java-11-openjdk (openSUSE-SU-2021:0719-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0719-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KGMX3TVL2LOHFGYNJZIU2YSG4IKEZZAM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the openSUSE-SU-2021:0719-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-11-openjdk fixes the following issues:

  - Update to upstream tag jdk-11.0.11+9 (April 2021 CPU)

  * CVE-2021-2163: Fixed incomplete enforcement of JAR signing disabled
         algorithms (bsc#1185055)

  * CVE-2021-2161: Fixed incorrect handling of partially quoted arguments
         in ProcessBuilder (bsc#1185056)

  - moved mozilla-nss dependency to java-11-openjdk-headless package, this
       is necessary to be able to do crypto with just java-11-openjdk-headless
       installed (bsc#1184606).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'java-11-openjdk' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk", rpm: "java-11-openjdk~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-accessibility", rpm: "java-11-openjdk-accessibility~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-accessibility-debuginfo", rpm: "java-11-openjdk-accessibility-debuginfo~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-debuginfo", rpm: "java-11-openjdk-debuginfo~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-debugsource", rpm: "java-11-openjdk-debugsource~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-demo", rpm: "java-11-openjdk-demo~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-devel", rpm: "java-11-openjdk-devel~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-headless", rpm: "java-11-openjdk-headless~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-jmods", rpm: "java-11-openjdk-jmods~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-src", rpm: "java-11-openjdk-src~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-javadoc", rpm: "java-11-openjdk-javadoc~11.0.11.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
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

