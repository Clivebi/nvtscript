if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876405" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2019-11372", "CVE-2019-11373" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-25 06:29:00 +0000 (Sat, 25 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-26 02:11:56 +0000 (Sun, 26 May 2019)" );
	script_name( "Fedora Update for libmediainfo FEDORA-2019-7155125125" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-7155125125" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XYF5I42OBJR7HKJD2OFS6LP26I52IT3M" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmediainfo'
  package(s) announced via the FEDORA-2019-7155125125 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the shared library for MediaInfo.
MediaInfo supplies technical and tag information about a video or
audio file.

What information can I get from MediaInfo?

  * General: title, author, director, album, track number, date, duration...

  * Video: codec, aspect, fps, bitrate...

  * Audio: codec, sample rate, channels, language, bitrate...

  * Text: language of subtitle

  * Chapters: number of chapters, list of chapters

DivX, XviD, H263, H.263, H264, x264, ASP, AVC, iTunes, MPEG-1,
MPEG1, MPEG-2, MPEG2, MPEG-4, MPEG4, MP4, M4A, M4V, QuickTime,
RealVideo, RealAudio, RA, RM, MSMPEG4v1, MSMPEG4v2, MSMPEG4v3,
VOB, DVD, WMA, VMW, ASF, 3GP, 3GPP, 3GP2

What format (container) does MediaInfo support?

  * Video: MKV, OGM, AVI, DivX, WMV, QuickTime, Real, MPEG-1,
  MPEG-2, MPEG-4, DVD (VOB) (Codecs: DivX, XviD, MSMPEG4, ASP,
  H.264, AVC...)

  * Audio: OGG, MP3, WAV, RA, AC3, DTS, AAC, M4A, AU, AIFF

  * Subtitles: SRT, SSA, ASS, SAMI" );
	script_tag( name: "affected", value: "'libmediainfo' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo", rpm: "libmediainfo~19.04~1.fc28", rls: "FC28" ) )){
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

