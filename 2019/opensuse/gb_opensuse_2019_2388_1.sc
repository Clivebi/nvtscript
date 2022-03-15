if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852751" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-16239" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-07 23:15:00 +0000 (Wed, 07 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-10-28 03:00:50 +0000 (Mon, 28 Oct 2019)" );
	script_name( "openSUSE: Security Advisory for openconnect (openSUSE-SU-2019:2388-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2388-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00061.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openconnect'
  package(s) announced via the openSUSE-SU-2019:2388-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openconnect fixes the following issues:

  - CVE-2019-16239: Fixed a buffer overflow when a malicious server uses
  HTTP chunked encoding with crafted chunk sizes. (bsc#1151178)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2388=1" );
	script_tag( name: "affected", value: "'openconnect' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "openconnect", rpm: "openconnect~7.08~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openconnect-debuginfo", rpm: "openconnect-debuginfo~7.08~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openconnect-debugsource", rpm: "openconnect-debugsource~7.08~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openconnect-devel", rpm: "openconnect-devel~7.08~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openconnect-doc", rpm: "openconnect-doc~7.08~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openconnect-lang", rpm: "openconnect-lang~7.08~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
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

