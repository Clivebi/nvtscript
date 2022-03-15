if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853367" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-17367", "CVE-2020-17368" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-10 11:15:00 +0000 (Sun, 10 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-08-15 03:01:05 +0000 (Sat, 15 Aug 2020)" );
	script_name( "openSUSE: Security Advisory for firejail (openSUSE-SU-2020:1208-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1208-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00036.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firejail'
  package(s) announced via the openSUSE-SU-2020:1208-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for firejail fixes the following issues:

  - CVE-2020-17367: The end-of-options separator -- was not handled
  correctly (boo#1174986).

  - CVE-2020-17368: An attacker who has control over the command line
  arguments could run arbitrary commands (boo#1174986).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1208=1" );
	script_tag( name: "affected", value: "'firejail' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "firejail", rpm: "firejail~0.9.62~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firejail-debuginfo", rpm: "firejail-debuginfo~0.9.62~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "firejail-debugsource", rpm: "firejail-debugsource~0.9.62~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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

