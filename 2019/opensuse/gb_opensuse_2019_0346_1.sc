if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852348" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2018-11212", "CVE-2019-2422" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-07 20:15:00 +0000 (Thu, 07 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-03-19 04:10:22 +0100 (Tue, 19 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for java-1_8_0-openjdk (openSUSE-SU-2019:0346-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0346-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00028.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-openjdk'
  package(s) announced via the openSUSE-SU-2019:0346-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_8_0-openjdk to version jdk8u201 (icedtea 3.11.0)
  fixes the following issues:

  Security issues fixed:

  - CVE-2019-2422: Fixed a memory disclosure in FileChannelImpl
  (bsc#1122293).

  - CVE-2018-11212: Fixed an issue in alloc_sarray function in jmemmgr.c
  (bsc#1122299).

  This update was imported from the SUSE:SLE-15:Update update project.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-346=1" );
	script_tag( name: "affected", value: "java-1_8_0-openjdk on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk", rpm: "java-1_8_0-openjdk~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-accessibility", rpm: "java-1_8_0-openjdk-accessibility~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debuginfo", rpm: "java-1_8_0-openjdk-debuginfo~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debugsource", rpm: "java-1_8_0-openjdk-debugsource~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo", rpm: "java-1_8_0-openjdk-demo~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo-debuginfo", rpm: "java-1_8_0-openjdk-demo-debuginfo~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel", rpm: "java-1_8_0-openjdk-devel~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel-debuginfo", rpm: "java-1_8_0-openjdk-devel-debuginfo~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless", rpm: "java-1_8_0-openjdk-headless~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless-debuginfo", rpm: "java-1_8_0-openjdk-headless-debuginfo~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-src", rpm: "java-1_8_0-openjdk-src~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-javadoc", rpm: "java-1_8_0-openjdk-javadoc~1.8.0.201~lp150.2.12.1", rls: "openSUSELeap15.0" ) )){
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

