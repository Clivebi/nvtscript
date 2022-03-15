if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852301" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2018-20230" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-19 04:07:27 +0100 (Tue, 19 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for pspp (openSUSE-SU-2019:0198-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0198-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00032.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pspp'
  package(s) announced via the openSUSE-SU-2019:0198-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for pspp to version 1.2.0 fixes the following issues:

  Security issue fixed:

  - CVE-2018-20230: Fixed a heap-based buffer overflow in
  read_bytes_internal function that could lead to denial-of-service
  (bsc#1120061).

  Other bug fixes and changes:

  - Add upstream patch to avoid compiling with old Texinfo 4.13.

  - New experimental command SAVE DATA COLLECTION to save MDD files.

  - MTIME and YMDHMS variable formats now supported.

  - Spread sheet rendering now done via spread-sheet-widget.

  This update introduces a new package called spread-sheet-widget as
  dependency.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-198=1" );
	script_tag( name: "affected", value: "pspp, on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libspread-sheet-widget0", rpm: "libspread-sheet-widget0~0.3~lp150.2.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspread-sheet-widget0-debuginfo", rpm: "libspread-sheet-widget0-debuginfo~0.3~lp150.2.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pspp", rpm: "pspp~1.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pspp-debuginfo", rpm: "pspp-debuginfo~1.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pspp-debugsource", rpm: "pspp-debugsource~1.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pspp-devel", rpm: "pspp-devel~1.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spread-sheet-widget-debugsource", rpm: "spread-sheet-widget-debugsource~0.3~lp150.2.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spread-sheet-widget-devel", rpm: "spread-sheet-widget-devel~0.3~lp150.2.1", rls: "openSUSELeap15.0" ) )){
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

