if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852805" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2019-12523", "CVE-2019-12525", "CVE-2019-12526", "CVE-2019-12527", "CVE-2019-12529", "CVE-2019-12854", "CVE-2019-13345", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679", "CVE-2019-3688" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-11 00:15:00 +0000 (Sat, 11 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:31:51 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for squid (openSUSE-SU-2019:2541-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2541-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00056.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the openSUSE-SU-2019:2541-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for squid to version 4.9 fixes the following issues:

  Security issues fixed:

  - CVE-2019-13345: Fixed multiple cross-site scripting vulnerabilities in
  cachemgr.cgi (bsc#1140738).

  - CVE-2019-12526: Fixed potential remote code execution during URN
  processing (bsc#1156326).

  - CVE-2019-12523, CVE-2019-18676: Fixed multiple improper validations in
  URI processing (bsc#1156329).

  - CVE-2019-18677: Fixed Cross-Site Request Forgery in HTTP Request
  processing (bsc#1156328).

  - CVE-2019-18678: Fixed incorrect message parsing which could have led to
  HTTP request splitting issue (bsc#1156323).

  - CVE-2019-18679: Fixed information disclosure when processing HTTP Digest
  Authentication (bsc#1156324).

  Other issues addressed:

  * Fixed DNS failures when peer name was configured with any upper case
  characters

  * Fixed several rock cache_dir corruption issues

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2541=1" );
	script_tag( name: "affected", value: "'squid' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "squid", rpm: "squid~4.9~lp151.2.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debuginfo", rpm: "squid-debuginfo~4.9~lp151.2.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debugsource", rpm: "squid-debugsource~4.9~lp151.2.7.1", rls: "openSUSELeap15.1" ) )){
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
