if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852830" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2019-16276", "CVE-2019-17596" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 13:19:00 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:34:19 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for go1.12 (openSUSE-SU-2019:2522-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2522-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00043.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'go1.12'
  package(s) announced via the openSUSE-SU-2019:2522-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for go1.12 fixes the following issues:

  Security issues fixed:

  - CVE-2019-16276: Fixed the handling of invalid HTTP headers, which had
  allowed request smuggling (bsc#1152082).

  - CVE-2019-17596: Fixed a panic in dsa.Verify caused by invalid public
  keys (bsc#1154402).

  Non-security issue fixed:

  - Go was updated to version 1.12.12 (bsc#1141689).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2522=1" );
	script_tag( name: "affected", value: "'go1.12' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "go1.12", rpm: "go1.12~1.12.12~lp151.2.25.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.12-doc", rpm: "go1.12-doc~1.12.12~lp151.2.25.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.12-race", rpm: "go1.12-race~1.12.12~lp151.2.25.1", rls: "openSUSELeap15.1" ) )){
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

