if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852469" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-9755" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-05-03 02:00:45 +0000 (Fri, 03 May 2019)" );
	script_name( "openSUSE: Security Advisory for ntfs-3g_ntfsprogs (openSUSE-SU-2019:1314-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1314-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00001.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntfs-3g_ntfsprogs'
  package(s) announced via the openSUSE-SU-2019:1314-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ntfs-3g_ntfsprogs fixes the following issues:

  Security issues fixed:

  - CVE-2019-9755: Fixed a heap-based buffer overflow which could lead to
  local privilege escalation (bsc#1130165).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1314=1" );
	script_tag( name: "affected", value: "'ntfs-3g_ntfsprogs' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libntfs-3g-devel", rpm: "libntfs-3g-devel~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libntfs-3g87", rpm: "libntfs-3g87~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libntfs-3g87-debuginfo", rpm: "libntfs-3g87-debuginfo~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g", rpm: "ntfs-3g~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g-debuginfo", rpm: "ntfs-3g-debuginfo~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g_ntfsprogs-debuginfo", rpm: "ntfs-3g_ntfsprogs-debuginfo~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g_ntfsprogs-debugsource", rpm: "ntfs-3g_ntfsprogs-debugsource~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfsprogs", rpm: "ntfsprogs~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfsprogs-debuginfo", rpm: "ntfsprogs-debuginfo~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfsprogs-extra", rpm: "ntfsprogs-extra~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfsprogs-extra-debuginfo", rpm: "ntfsprogs-extra-debuginfo~2016.2.22~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

