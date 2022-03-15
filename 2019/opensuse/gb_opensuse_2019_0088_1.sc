if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852251" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-0734", "CVE-2018-12116", "CVE-2018-12120", "CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123", "CVE-2018-5407" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-01-26 04:01:52 +0100 (Sat, 26 Jan 2019)" );
	script_name( "openSUSE: Security Advisory for nodejs4 (openSUSE-SU-2019:0088-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0088-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00035.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs4'
  package(s) announced via the openSUSE-SU-2019:0088-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs4 fixes the following issues:

  Security issues fixed:

  - CVE-2018-0734: Fixed a timing vulnerability in the DSA signature
  generation (bsc#1113652)

  - CVE-2018-5407: Fixed a hyperthread port content side channel attack (aka
  'PortSmash') (bsc#1113534)

  - CVE-2018-12120: Fixed that the debugger listens on any interface by
  default (bsc#1117625)

  - CVE-2018-12121: Fixed a denial of Service with large HTTP headers
  (bsc#1117626)

  - CVE-2018-12122: Fixed the 'Slowloris' HTTP Denial of Service
  (bsc#1117627)

  - CVE-2018-12116: Fixed HTTP request splitting (bsc#1117630)

  - CVE-2018-12123: Fixed hostname spoofing in URL parser for javascript
  protocol (bsc#1117629)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-88=1" );
	script_tag( name: "affected", value: "nodejs4 on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs4", rpm: "nodejs4~4.9.1~20.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debuginfo", rpm: "nodejs4-debuginfo~4.9.1~20.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debugsource", rpm: "nodejs4-debugsource~4.9.1~20.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-devel", rpm: "nodejs4-devel~4.9.1~20.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm4", rpm: "npm4~4.9.1~20.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-docs", rpm: "nodejs4-docs~4.9.1~20.1", rls: "openSUSELeap42.3" ) )){
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

