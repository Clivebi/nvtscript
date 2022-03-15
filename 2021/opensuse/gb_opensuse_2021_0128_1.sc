if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853642" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-3139" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-22 18:25:00 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:59 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for tcmu-runner (openSUSE-SU-2021:0128-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0128-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JYQLRIH544YEAMHU4GAXRYAFN2OW7FVX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tcmu-runner'
  package(s) announced via the openSUSE-SU-2021:0128-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tcmu-runner fixes the following issue:

  - CVE-2021-3139: Fixed a LIO security issue (bsc#1180676).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'tcmu-runner' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtcmu2", rpm: "libtcmu2~1.4.0~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtcmu2-debuginfo", rpm: "libtcmu2-debuginfo~1.4.0~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcmu-runner", rpm: "tcmu-runner~1.4.0~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcmu-runner-debuginfo", rpm: "tcmu-runner-debuginfo~1.4.0~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcmu-runner-debugsource", rpm: "tcmu-runner-debugsource~1.4.0~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcmu-runner-handler-rbd", rpm: "tcmu-runner-handler-rbd~1.4.0~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcmu-runner-handler-rbd-debuginfo", rpm: "tcmu-runner-handler-rbd-debuginfo~1.4.0~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
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

