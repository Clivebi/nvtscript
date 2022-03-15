if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853285" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-4044" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-14 21:15:00 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-19 03:01:27 +0000 (Sun, 19 Jul 2020)" );
	script_name( "openSUSE: Security Advisory for xrdp (openSUSE-SU-2020:0999-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0999-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00036.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xrdp'
  package(s) announced via the openSUSE-SU-2020:0999-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xrdp fixes the following issues:

  - Security fixes (bsc#1173580, CVE-2020-4044):
  + Add patches:

  * xrdp-cve-2020-4044-fix-0.patch

  * xrdp-cve-2020-4044-fix-1.patch
  + Rebase SLE patch:

  * xrdp-fate318398-change-expired-password.patch

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-999=1" );
	script_tag( name: "affected", value: "'xrdp' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpainter0", rpm: "libpainter0~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpainter0-debuginfo", rpm: "libpainter0-debuginfo~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librfxencode0", rpm: "librfxencode0~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librfxencode0-debuginfo", rpm: "librfxencode0-debuginfo~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xrdp", rpm: "xrdp~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xrdp-debuginfo", rpm: "xrdp-debuginfo~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xrdp-debugsource", rpm: "xrdp-debugsource~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xrdp-devel", rpm: "xrdp-devel~0.9.6~lp151.4.6.1", rls: "openSUSELeap15.1" ) )){
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

