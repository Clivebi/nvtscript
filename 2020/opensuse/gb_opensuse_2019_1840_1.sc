if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852875" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2018-19857", "CVE-2019-12874", "CVE-2019-13602", "CVE-2019-13962", "CVE-2019-5439", "CVE-2019-5459", "CVE-2019-5460" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-25 12:15:00 +0000 (Tue, 25 Jun 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:40:19 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for vlc (openSUSE-SU-2019:1840-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:1840-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00005.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vlc'
  package(s) announced via the openSUSE-SU-2019:1840-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for vlc to version 3.0.7.1 fixes the following issues:

  Security issues fixed:

  - CVE-2019-5439: Fixed a buffer overflow (bsc#1138354).

  - CVE-2019-5459: Fixed an integer underflow (bsc#1143549).

  - CVE-2019-5460: Fixed a double free (bsc#1143547).

  - CVE-2019-12874: Fixed a double free in zlib_decompress_extra in
  modules/demux/mkv/util.cpp (bsc#1138933).

  - CVE-2019-13602: Fixed an integer underflow in mp4 demuxer (boo#1141522).

  - CVE-2019-13962: Fixed a heap-based buffer over-read in avcodec
  (boo#1142161).

  Non-security issues fixed:

  - Video Output:

  * Fix hardware acceleration with some AMD drivers

  * Improve direct3d11 HDR support

  - Access:

  * Improve Blu-ray support

  - Audio output:

  * Fix pass-through on Android-23

  * Fix DirectSound drain

  - Demux: Improve MP4 support

  - Video Output:

  * Fix 12 bits sources playback with Direct3D11

  * Fix crash on iOS

  * Fix midstream aspect-ratio changes when Windows hardware decoding is on

  * Fix HLG display with Direct3D11

  - Stream Output: Improve Chromecast support with new ChromeCast apps

  - Misc:

  * Update Youtube, Dailymotion, Vimeo, Soundcloud scripts

  * Work around busy looping when playing an invalid item with loop enabled

  - Updated translations.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1840=1" );
	script_tag( name: "affected", value: "'vlc' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvlc5", rpm: "libvlc5~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlc5-debuginfo", rpm: "libvlc5-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlccore9", rpm: "libvlccore9~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlccore9-debuginfo", rpm: "libvlccore9-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc", rpm: "vlc~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-codec-gstreamer", rpm: "vlc-codec-gstreamer~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-codec-gstreamer-debuginfo", rpm: "vlc-codec-gstreamer-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-debuginfo", rpm: "vlc-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-debugsource", rpm: "vlc-debugsource~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-devel", rpm: "vlc-devel~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-jack", rpm: "vlc-jack~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-jack-debuginfo", rpm: "vlc-jack-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX", rpm: "vlc-noX~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX-debuginfo", rpm: "vlc-noX-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-qt", rpm: "vlc-qt~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-qt-debuginfo", rpm: "vlc-qt-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-vdpau", rpm: "vlc-vdpau~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-vdpau-debuginfo", rpm: "vlc-vdpau-debuginfo~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-lang", rpm: "vlc-lang~3.0.7.1~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
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

