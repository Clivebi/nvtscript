if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852473" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-2602", "CVE-2019-2684" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-05-05 02:00:39 +0000 (Sun, 05 May 2019)" );
	script_name( "openSUSE: Security Advisory for java-11-openjdk (openSUSE-SU-2019:1327-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1327-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00007.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the openSUSE-SU-2019:1327-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-11-openjdk to version 11.0.3+7 fixes the following
  issues:

  Security issues fixed:

  - CVE-2019-2602: Fixed excessive use of CPU time in the BigDecimal
  implementation (bsc#1132728).

  - CVE-2019-2684: Fixed a flaw in the RMI registry implementation which
  could lead to selection of an incorrect skeleton class (bsc#1132732).

  Non-security issues fixed:

  - Multiple bug fixes and improvements.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1327=1" );
	script_tag( name: "affected", value: "'java-11-openjdk' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-javadoc", rpm: "java-11-openjdk-javadoc~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk", rpm: "java-11-openjdk~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-accessibility", rpm: "java-11-openjdk-accessibility~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-accessibility-debuginfo", rpm: "java-11-openjdk-accessibility-debuginfo~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-debuginfo", rpm: "java-11-openjdk-debuginfo~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-debugsource", rpm: "java-11-openjdk-debugsource~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-demo", rpm: "java-11-openjdk-demo~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-devel", rpm: "java-11-openjdk-devel~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-headless", rpm: "java-11-openjdk-headless~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-jmods", rpm: "java-11-openjdk-jmods~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-src", rpm: "java-11-openjdk-src~11.0.3.0~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
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

