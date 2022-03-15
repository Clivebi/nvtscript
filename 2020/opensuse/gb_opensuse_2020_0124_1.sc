if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853020" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-18899", "CVE-2020-5202" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-03 18:59:00 +0000 (Thu, 03 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-01-30 04:01:14 +0000 (Thu, 30 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for apt-cacher-ng (openSUSE-SU-2020:0124_1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0124-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00057.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apt-cacher-ng'
  package(s) announced via the openSUSE-SU-2020:0124-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for apt-cacher-ng fixes the following issues:

  - CVE-2019-18899: Fixed a symlink attack which could allow to overwrite
  arbitrary data (boo#1157703).

  - CVE-2020-5202: Fixed an information leak if a local user won a race
  condition to listen to localhost:3142 (boo#1157706).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-124=1" );
	script_tag( name: "affected", value: "'apt-cacher-ng' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "apt-cacher-ng", rpm: "apt-cacher-ng~3.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apt-cacher-ng-debuginfo", rpm: "apt-cacher-ng-debuginfo~3.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apt-cacher-ng-debugsource", rpm: "apt-cacher-ng-debugsource~3.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

