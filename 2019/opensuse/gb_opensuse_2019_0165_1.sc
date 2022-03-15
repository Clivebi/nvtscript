if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852285" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2018-19198", "CVE-2018-19199", "CVE-2018-19200", "CVE-2018-20721" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-02-14 04:05:05 +0100 (Thu, 14 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for uriparser (openSUSE-SU-2019:0165-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0165-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00016.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'uriparser'
  package(s) announced via the openSUSE-SU-2019:0165-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for uriparser fixes the following issues:

  Security issues fixed:

  - CVE-2018-20721: Fixed an out-of-bounds read for incomplete URIs with
  IPv6 addresses with embedded IPv4 address (bsc#1122193).

  - CVE-2018-19198: Fixed an out-of-bounds write that was possible via the
  uriComposeQuery* or uriComposeQueryEx* function (bsc#1115722).

  - CVE-2018-19199: Fixed an integer overflow caused by an unchecked
  multiplication via the uriComposeQuery* or uriComposeQueryEx* function
  (bsc#1115723).

  - CVE-2018-19200: Fixed an operation attempted on NULL input via a
  uriResetUri* function (bsc#1115724).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-165=1" );
	script_tag( name: "affected", value: "uriparser on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "liburiparser1", rpm: "liburiparser1~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liburiparser1-debuginfo", rpm: "liburiparser1-debuginfo~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uriparser", rpm: "uriparser~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uriparser-debuginfo", rpm: "uriparser-debuginfo~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uriparser-debugsource", rpm: "uriparser-debugsource~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uriparser-devel", rpm: "uriparser-devel~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liburiparser1-32bit", rpm: "liburiparser1-32bit~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liburiparser1-32bit-debuginfo", rpm: "liburiparser1-32bit-debuginfo~0.8.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

