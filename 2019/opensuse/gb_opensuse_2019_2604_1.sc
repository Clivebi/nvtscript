if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852793" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2019-17177", "CVE-2019-17178" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 18:13:00 +0000 (Wed, 14 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-12-02 03:00:43 +0000 (Mon, 02 Dec 2019)" );
	script_name( "openSUSE: Security Advisory for freerdp (openSUSE-SU-2019:2604-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2604-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-12/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp'
  package(s) announced via the openSUSE-SU-2019:2604-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for freerdp fixes the following issues:

  - CVE-2019-17177: Fixed multiple memory leaks in libfreerdp/codec/region.c
  (bsc#1153163).

  - CVE-2019-17178: Fixed a memory leak in HuffmanTree_makeFromFrequencies
  (bsc#1153164).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2604=1" );
	script_tag( name: "affected", value: "'freerdp' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "freerdp", rpm: "freerdp~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debuginfo", rpm: "freerdp-debuginfo~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debugsource", rpm: "freerdp-debugsource~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-devel", rpm: "freerdp-devel~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-server", rpm: "freerdp-server~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-server-debuginfo", rpm: "freerdp-server-debuginfo~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-wayland", rpm: "freerdp-wayland~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-wayland-debuginfo", rpm: "freerdp-wayland-debuginfo~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2", rpm: "libfreerdp2~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2-debuginfo", rpm: "libfreerdp2-debuginfo~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuwac0-0", rpm: "libuwac0-0~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuwac0-0-debuginfo", rpm: "libuwac0-0-debuginfo~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwinpr2", rpm: "libwinpr2~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwinpr2-debuginfo", rpm: "libwinpr2-debuginfo~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uwac0-0-devel", rpm: "uwac0-0-devel~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "winpr2-devel", rpm: "winpr2-devel~2.0.0~rc4~lp150.10.1", rls: "openSUSELeap15.0" ) )){
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

