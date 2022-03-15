if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879343" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2020-26797" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-06 03:15:00 +0000 (Tue, 06 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-06 03:17:25 +0000 (Tue, 06 Apr 2021)" );
	script_name( "Fedora: Security Advisory for mediainfo (FEDORA-2021-3b67623d93)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-3b67623d93" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AZGJQQT3RJWJ46M75Y4OJ6GQVOXTHUGZ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediainfo'
  package(s) announced via the FEDORA-2021-3b67623d93 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MediaInfo CLI (Command Line Interface).

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

  * Subtitles: SRT, SSA, ASS, S-MI" );
	script_tag( name: "affected", value: "'mediainfo' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "mediainfo", rpm: "mediainfo~21.03~1.fc33", rls: "FC33" ) )){
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

