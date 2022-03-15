if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853497" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2020-24368" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 18:15:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-17 03:00:56 +0000 (Sat, 17 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for icingaweb2 (openSUSE-SU-2020:1674-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap15\\.2|openSUSELeap15\\.1)" );
	script_xref( name: "openSUSE-SU", value: "2020:1674-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00028.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icingaweb2'
  package(s) announced via the openSUSE-SU-2020:1674-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for icingaweb2 fixes the following issues:

  - icingaweb2 was updated to 2.7.4

  * CVE-2020-24368: Fixed a path Traversal which could have allowed an
  attacker to access arbitrary files which are readable by the process
  running (boo#1175530).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1674=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1674=1

  - openSUSE Backports SLE-15-SP2:

  zypper in -t patch openSUSE-2020-1674=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-1674=1

  - SUSE Package Hub for SUSE Linux Enterprise 12:

  zypper in -t patch openSUSE-2020-1674=1" );
	script_tag( name: "affected", value: "'icingaweb2' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "icingacli", rpm: "icingacli~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2", rpm: "icingaweb2~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-common", rpm: "icingaweb2-common~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-HTMLPurifier", rpm: "icingaweb2-vendor-HTMLPurifier~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-JShrink", rpm: "icingaweb2-vendor-JShrink~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-Parsedown", rpm: "icingaweb2-vendor-Parsedown~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-dompdf", rpm: "icingaweb2-vendor-dompdf~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-lessphp", rpm: "icingaweb2-vendor-lessphp~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-zf1", rpm: "icingaweb2-vendor-zf1~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-Icinga", rpm: "php-Icinga~2.7.4~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "icingacli", rpm: "icingacli~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2", rpm: "icingaweb2~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-common", rpm: "icingaweb2-common~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-HTMLPurifier", rpm: "icingaweb2-vendor-HTMLPurifier~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-JShrink", rpm: "icingaweb2-vendor-JShrink~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-Parsedown", rpm: "icingaweb2-vendor-Parsedown~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-dompdf", rpm: "icingaweb2-vendor-dompdf~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-lessphp", rpm: "icingaweb2-vendor-lessphp~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icingaweb2-vendor-zf1", rpm: "icingaweb2-vendor-zf1~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-Icinga", rpm: "php-Icinga~2.7.4~lp151.6.8.1", rls: "openSUSELeap15.1" ) )){
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

