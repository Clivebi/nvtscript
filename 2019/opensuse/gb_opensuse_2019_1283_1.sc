if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852455" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2017-12627" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-31 01:29:00 +0000 (Sat, 31 Mar 2018)" );
	script_tag( name: "creation_date", value: "2019-04-27 02:00:26 +0000 (Sat, 27 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for xerces-c (openSUSE-SU-2019:1283-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1283-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00099.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xerces-c'
  package(s) announced via the openSUSE-SU-2019:1283-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xerces-c fixes the following issue:

  - CVE-2017-12627: Processing of external DTD paths could have resulted in
  a null pointer dereference under certain conditions (bsc#1083630)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1283=1" );
	script_tag( name: "affected", value: "'xerces-c' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libxerces-c-3_1", rpm: "libxerces-c-3_1~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxerces-c-3_1-debuginfo", rpm: "libxerces-c-3_1-debuginfo~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxerces-c-devel", rpm: "libxerces-c-devel~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-c", rpm: "xerces-c~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-c-debuginfo", rpm: "xerces-c-debuginfo~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-c-debugsource", rpm: "xerces-c-debugsource~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-c-doc", rpm: "xerces-c-doc~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxerces-c-3_1-32bit", rpm: "libxerces-c-3_1-32bit~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxerces-c-3_1-32bit-debuginfo", rpm: "libxerces-c-3_1-32bit-debuginfo~3.1.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

