if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853240" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2020-8177" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-01 00:15:00 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-06-30 03:00:49 +0000 (Tue, 30 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for curl (openSUSE-SU-2020:0908-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0908-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00072.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the openSUSE-SU-2020:0908-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for curl fixes the following issues:

  - CVE-2020-8177: Fixed an issue where curl could have been tricked by a
  malicious server to overwrite a local file when using the -J option
  (bsc#1173027).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-908=1" );
	script_tag( name: "affected", value: "'curl' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debuginfo", rpm: "curl-debuginfo~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debugsource", rpm: "curl-debugsource~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-mini", rpm: "curl-mini~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-mini-debuginfo", rpm: "curl-mini-debuginfo~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-mini-debugsource", rpm: "curl-mini-debugsource~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel", rpm: "libcurl-devel~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-mini-devel", rpm: "libcurl-mini-devel~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4", rpm: "libcurl4~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-debuginfo", rpm: "libcurl4-debuginfo~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-mini", rpm: "libcurl4-mini~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-mini-debuginfo", rpm: "libcurl4-mini-debuginfo~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel-32bit", rpm: "libcurl-devel-32bit~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit", rpm: "libcurl4-32bit~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit-debuginfo", rpm: "libcurl4-32bit-debuginfo~7.60.0~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
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

