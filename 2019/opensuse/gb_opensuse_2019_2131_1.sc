if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852700" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2018-20060", "CVE-2019-11236", "CVE-2019-11324", "CVE-2019-9740" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 21:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-09-15 02:00:37 +0000 (Sun, 15 Sep 2019)" );
	script_name( "openSUSE: Security Advisory for python-urllib3 (openSUSE-SU-2019:2131-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2131-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00039.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-urllib3'
  package(s) announced via the openSUSE-SU-2019:2131-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-urllib3 fixes the following issues:

  Security issues fixed:

  - CVE-2019-9740: Fixed CRLF injection issue (bsc#1129071).

  - CVE-2019-11324: Fixed invalid CA certificate verification (bsc#1132900).

  - CVE-2019-11236: Fixed CRLF injection via request parameter (bsc#1132663).

  - CVE-2018-20060: Remove Authorization header when redirecting cross-host
  (bsc#1119376).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2131=1" );
	script_tag( name: "affected", value: "'python-urllib3' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "python2-urllib3", rpm: "python2-urllib3~1.22~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-urllib3", rpm: "python3-urllib3~1.22~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
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

