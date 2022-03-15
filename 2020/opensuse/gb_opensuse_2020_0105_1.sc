if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853010" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-2126", "CVE-2019-9232", "CVE-2019-9325", "CVE-2019-9371", "CVE-2019-9433" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-25 16:15:00 +0000 (Mon, 25 Nov 2019)" );
	script_tag( name: "creation_date", value: "2020-01-27 09:18:47 +0000 (Mon, 27 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for libvpx (openSUSE-SU-2020:0105_1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0105-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00049.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvpx'
  package(s) announced via the openSUSE-SU-2020:0105-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libvpx fixes the following issues:

  - CVE-2019-2126: Fixed a double free in ParseContentEncodingEntry()
  (bsc#1160611).

  - CVE-2019-9325: Fixed an out-of-bounds read (bsc#1160612).

  - CVE-2019-9232: Fixed an out-of-bounds memory access on fuzzed data
  (bsc#1160613).

  - CVE-2019-9433: Fixed a use-after-free in vp8_deblock() (bsc#1160614).

  - CVE-2019-9371: Fixed a resource exhaustion after memory leak
  (bsc#1160615).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-105=1" );
	script_tag( name: "affected", value: "'libvpx' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvpx-debugsource", rpm: "libvpx-debugsource~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx-devel", rpm: "libvpx-devel~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4", rpm: "libvpx4~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4-debuginfo", rpm: "libvpx4-debuginfo~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vpx-tools", rpm: "vpx-tools~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vpx-tools-debuginfo", rpm: "vpx-tools-debuginfo~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4-32bit", rpm: "libvpx4-32bit~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvpx4-32bit-debuginfo", rpm: "libvpx4-32bit-debuginfo~1.6.1~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
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

