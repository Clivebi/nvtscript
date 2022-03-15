if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853578" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-14556", "CVE-2020-14577", "CVE-2020-14578", "CVE-2020-14579", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621", "CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14798", "CVE-2020-14803" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 04:01:39 +0000 (Wed, 11 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for java-1_8_0-openj9 (openSUSE-SU-2020:1893-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1893-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00041.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-openj9'
  package(s) announced via the openSUSE-SU-2020:1893-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_8_0-openj9 fixes the following issues:

  - OpenJDK was updated to 8u2732 build 10 with OpenJ9 0.23.0 virtual machine

  - includes Oracle July 2020 (bsc#1174157) and October 2020 CPU
  (bsc#1177943)

  - CVE-2020-14556, CVE-2020-14577, CVE-2020-14578, CVE-2020-14579,
  CVE-2020-14581, CVE-2020-14583, CVE-2020-14593, CVE-2020-14621,
  CVE-2020-14779, CVE-2020-14781, CVE-2020-14782, CVE-2020-14792,
  CVE-2020-14796, CVE-2020-14797, CVE-2020-14798 and CVE-2020-14803

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1893=1" );
	script_tag( name: "affected", value: "'java-1_8_0-openj9' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9", rpm: "java-1_8_0-openj9~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-accessibility", rpm: "java-1_8_0-openj9-accessibility~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-debuginfo", rpm: "java-1_8_0-openj9-debuginfo~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-debugsource", rpm: "java-1_8_0-openj9-debugsource~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-demo", rpm: "java-1_8_0-openj9-demo~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-demo-debuginfo", rpm: "java-1_8_0-openj9-demo-debuginfo~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-devel", rpm: "java-1_8_0-openj9-devel~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-headless", rpm: "java-1_8_0-openj9-headless~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-src", rpm: "java-1_8_0-openj9-src~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openj9-javadoc", rpm: "java-1_8_0-openj9-javadoc~1.8.0.272~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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

