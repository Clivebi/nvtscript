if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852280" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2016-9015" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-13 13:09:00 +0000 (Fri, 13 Jan 2017)" );
	script_tag( name: "creation_date", value: "2019-02-13 04:04:35 +0100 (Wed, 13 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for python-urllib3 (openSUSE-SU-2019:0159-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0159-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00014.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-urllib3'
  package(s) announced via the openSUSE-SU-2019:0159-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-urllib3 fixes the following issues:

  python-urllib3 was updated to version 1.22 (fate#326733, bsc#1110422) and
  contains new features and lots of bugfixes:

  Security issues fixed:

  - CVE-2016-9015: TLS certificate validation vulnerability (bsc#1024540).
  (This issue did not affect our previous version 1.16.)

  Non security issues fixed:

  - bsc#1074247: Fix test suite, use correct date (gh#shazow/urllib3#1303).

  This update was imported from the SUSE:SLE-12-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-159=1" );
	script_tag( name: "affected", value: "python-urllib3 on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "python-urllib3", rpm: "python-urllib3~1.22~4.4.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-urllib3", rpm: "python3-urllib3~1.22~4.4.1", rls: "openSUSELeap42.3" ) )){
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

