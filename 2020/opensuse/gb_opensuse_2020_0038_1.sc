if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852980" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-10072", "CVE-2019-12418", "CVE-2019-17563" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-01-14 04:01:15 +0000 (Tue, 14 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for tomcat (openSUSE-SU-2020:0038-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0038-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00013.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat'
  package(s) announced via the openSUSE-SU-2020:0038-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tomcat to version 9.0.30 fixes the following issues:

  Security issue fixed:

  - CVE-2019-12418: Fixed a local privilege escalation through by
  manipulating the RMI registry and performing a man-in-the-middle attack
  (bsc#1159723).

  - CVE-2019-17563: Fixed a session fixation attack when using FORM
  authentication (bsc#1159729).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-38=1" );
	script_tag( name: "affected", value: "'tomcat' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-3_0-api", rpm: "tomcat-el-3_0-api~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-embed", rpm: "tomcat-embed~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2_3-api", rpm: "tomcat-jsp-2_3-api~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsvc", rpm: "tomcat-jsvc~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-4_0-api", rpm: "tomcat-servlet-4_0-api~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~9.0.30~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
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

