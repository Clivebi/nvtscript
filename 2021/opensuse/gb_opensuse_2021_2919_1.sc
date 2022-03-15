if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854132" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-9721", "CVE-2020-21688", "CVE-2020-21697", "CVE-2020-22046", "CVE-2020-22048", "CVE-2020-22049", "CVE-2020-22054", "CVE-2021-38114" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-16 18:15:00 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-09-03 01:02:37 +0000 (Fri, 03 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for ffmpeg (openSUSE-SU-2021:2919-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2919-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RHYNSW2TAJSSTZPOYXQXGZDI6LYBWIT4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the openSUSE-SU-2021:2919-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ffmpeg fixes the following issues:

  - CVE-2019-9721: Fix denial of service in the subtitle decoder in
       handle_open_brace from libavcodec/htmlsubtitles.c (bsc#1129714).

  - CVE-2020-22046: Fix a denial of service vulnerability exists in FFmpeg
       4.2 due to a memory leak in the avpriv_float_dsp_allocl function in
       libavutil/float_dsp.c (bsc#1186849).

  - CVE-2020-22048: Fix a denial of service vulnerability exists in FFmpeg
       4.2 due to a memory leak in the ff_frame_pool_get function in
       framepool.c (bsc#1186859).

  - CVE-2020-22049: Fix a denial of service vulnerability exists in FFmpeg
       4.2 due to a memory leak in the wtvfile_open_sector function in wtvdec.c
       (bsc#1186861).

  - CVE-2020-22054: Fix a denial of service vulnerability exists in FFmpeg
       4.2 due to a memory leak in the av_dict_set function in dict.c
       (bsc#1186863).

  - CVE-2020-21688: Fixed a heap-use-after-free in the av_freep function in
       libavutil/mem.c (bsc#1189348).

  - CVE-2020-21697: Fixed a heap-use-after-free in the mpeg_mux_write_packet
       function in libavformat/mpegenc.c (bsc#1189350).

  - CVE-2021-38114: Fixed a not checked return value of the init_vlc
       function (bsc#1189142)." );
	script_tag( name: "affected", value: "'ffmpeg' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "ffmpeg", rpm: "ffmpeg~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ffmpeg-debuginfo", rpm: "ffmpeg-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ffmpeg-debugsource", rpm: "ffmpeg-debugsource~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ffmpeg-private-devel", rpm: "ffmpeg-private-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavcodec-devel", rpm: "libavcodec-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavcodec57", rpm: "libavcodec57~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavcodec57-debuginfo", rpm: "libavcodec57-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavdevice-devel", rpm: "libavdevice-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavdevice57", rpm: "libavdevice57~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavdevice57-debuginfo", rpm: "libavdevice57-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavfilter-devel", rpm: "libavfilter-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavfilter6", rpm: "libavfilter6~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavfilter6-debuginfo", rpm: "libavfilter6-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavformat-devel", rpm: "libavformat-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavformat57", rpm: "libavformat57~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavformat57-debuginfo", rpm: "libavformat57-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavresample-devel", rpm: "libavresample-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavresample3", rpm: "libavresample3~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavresample3-debuginfo", rpm: "libavresample3-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavutil-devel", rpm: "libavutil-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavutil55", rpm: "libavutil55~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavutil55-debuginfo", rpm: "libavutil55-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpostproc-devel", rpm: "libpostproc-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpostproc54", rpm: "libpostproc54~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpostproc54-debuginfo", rpm: "libpostproc54-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswresample-devel", rpm: "libswresample-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswresample2", rpm: "libswresample2~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswresample2-debuginfo", rpm: "libswresample2-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswscale-devel", rpm: "libswscale-devel~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswscale4", rpm: "libswscale4~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswscale4-debuginfo", rpm: "libswscale4-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavcodec57-32bit", rpm: "libavcodec57-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavcodec57-32bit-debuginfo", rpm: "libavcodec57-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavdevice57-32bit", rpm: "libavdevice57-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavdevice57-32bit-debuginfo", rpm: "libavdevice57-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavfilter6-32bit", rpm: "libavfilter6-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavfilter6-32bit-debuginfo", rpm: "libavfilter6-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavformat57-32bit", rpm: "libavformat57-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavformat57-32bit-debuginfo", rpm: "libavformat57-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavresample3-32bit", rpm: "libavresample3-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavresample3-32bit-debuginfo", rpm: "libavresample3-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavutil55-32bit", rpm: "libavutil55-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavutil55-32bit-debuginfo", rpm: "libavutil55-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpostproc54-32bit", rpm: "libpostproc54-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpostproc54-32bit-debuginfo", rpm: "libpostproc54-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswresample2-32bit", rpm: "libswresample2-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswresample2-32bit-debuginfo", rpm: "libswresample2-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswscale4-32bit", rpm: "libswscale4-32bit~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libswscale4-32bit-debuginfo", rpm: "libswscale4-32bit-debuginfo~3.4.2~11.8.2", rls: "openSUSELeap15.3" ) )){
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

