if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852671" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2017-16808", "CVE-2019-1010220" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-02 16:15:00 +0000 (Wed, 02 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-08-21 02:00:59 +0000 (Wed, 21 Aug 2019)" );
	script_name( "openSUSE: Security Advisory for tcpdump (openSUSE-SU-2019:1964-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1964-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00065.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tcpdump'
  package(s) announced via the openSUSE-SU-2019:1964-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tcpdump fixes the following issues:

  Security issues fixed:

  - CVE-2019-1010220: Fixed a buffer over-read in print_prefix() which may
  expose data (bsc#1142439).

  - CVE-2017-16808: Fixed a heap-based buffer over-read related to
  aoe_print() and lookup_emem() (bsc#1068716).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1964=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1964=1" );
	script_tag( name: "affected", value: "'tcpdump' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "tcpdump", rpm: "tcpdump~4.9.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcpdump-debuginfo", rpm: "tcpdump-debuginfo~4.9.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tcpdump-debugsource", rpm: "tcpdump-debugsource~4.9.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
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

