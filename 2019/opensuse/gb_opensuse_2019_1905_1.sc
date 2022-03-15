if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852655" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2019-12594", "CVE-2019-7165" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-16 02:01:10 +0000 (Fri, 16 Aug 2019)" );
	script_name( "openSUSE: Security Advisory for dosbox (openSUSE-SU-2019:1905-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1905-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00047.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dosbox'
  package(s) announced via the openSUSE-SU-2019:1905-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dosbox fixes the following issues:

  Security issues fixed:

  - CVE-2019-7165: Fixed that a very long line inside a bat file would
  overflow the parsing buffer (bnc#1140254).

  - CVE-2019-12594: Added a basic permission system so that a program
  running inside DOSBox can't access the contents of /proc (e.g.
  /proc/self/mem) when / or /proc were (to be) mounted (bnc#1140254).

  - Several other fixes for out of bounds access and buffer overflows.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1905=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1905=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1905=1" );
	script_tag( name: "affected", value: "'dosbox' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "dosbox", rpm: "dosbox~0.74.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dosbox-debuginfo", rpm: "dosbox-debuginfo~0.74.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dosbox-debugsource", rpm: "dosbox-debugsource~0.74.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

