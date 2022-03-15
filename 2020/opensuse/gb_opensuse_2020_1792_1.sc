if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853549" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2020-11993", "CVE-2020-9490" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:01:47 +0000 (Tue, 03 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for apache2 (openSUSE-SU-2020:1792-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1792-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00081.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the openSUSE-SU-2020:1792-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for apache2 fixes the following issues:

  - Enables the patch for CVE-2020-11993 and CVE-2020-9490. The patch was
  included but not applied in the previous update. (bsc#1178074)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1792=1" );
	script_tag( name: "affected", value: "'apache2' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-debuginfo", rpm: "apache2-debuginfo~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-debugsource", rpm: "apache2-debugsource~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-devel", rpm: "apache2-devel~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-event", rpm: "apache2-event~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-event-debuginfo", rpm: "apache2-event-debuginfo~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork-debuginfo", rpm: "apache2-prefork-debuginfo~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils-debuginfo", rpm: "apache2-utils-debuginfo~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker-debuginfo", rpm: "apache2-worker-debuginfo~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.4.33~lp151.8.21.1", rls: "openSUSELeap15.1" ) )){
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
