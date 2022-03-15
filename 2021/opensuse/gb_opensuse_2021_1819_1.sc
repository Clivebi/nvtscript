if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853973" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-3185" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 21:30:00 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:08:22 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for gstreamer, (openSUSE-SU-2021:1819-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1819-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4DDS7NLC6D7UVP25OVRWIRK6Y44WZKCU" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer, '
  package(s) announced via the openSUSE-SU-2021:1819-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gstreamer, gstreamer-plugins-bad, gstreamer-plugins-base,
     gstreamer-plugins-good, gstreamer-plugins-ugly fixes the following issues:

     gstreamer was updated to version 1.16.3 (bsc#1181255):

  - delay creation of threadpools

  - bin: Fix `deep-element-removed` log message

  - buffer: fix meta sequence number fallback on rpi

  - bufferlist: foreach: always remove as parent if buffer is changed

  - bus: Make setting/replacing/clearing the sync handler thread-safe

  - elementfactory: Fix missing features in case a feature moves to another
       filename

  - element: When removing a ghost pad also unset its target

  - meta: intern registered impl string

  - registry: Use a toolchain-specific registry file on Windows

  - systemclock: Invalid internal time calculation causes non-increasing
       clock time on Windows

  - value: don&#x27 t write to `const char *`

  - value: Fix segfault comparing empty GValueArrays

  - Revert floating enforcing

  - aggregator: fix iteration direction in skip_buffers

  - sparsefile: fix possible crash when seeking

  - baseparse: cache fix

  - baseparse: fix memory leak when subclass skips whole input buffer

  - baseparse: Set the private duration before posting a duration-changed
       message

  - basetransform: allow not passthrough if generate_output is implemented

  - identity: Fix a minor leak using meta_str

  - queue: protect against lost wakeups for iterm_del condition

  - queue2: Avoid races when posting buffering messages

  - queue2: Fix missing/dropped buffering messages at startup

  - identity: Unblock condition variable on FLUSH_START

  - check: Use `g_thread_yield()` instead of `g_usleep(1)`

  - tests: use cpu_family for arch checks

  - gst-launch: Follow up to missing `s/g_print/gst_print/g`

  - gst-inspect: Add define guard for `g_log_writer_supports_color()`

  - gst-launch: go back down to `GST_STATE_NULL` in one step.

  - device-monitor: list hidden providers before listing devices

  - autotools build fixes for GNU make 4.3

     gstreamer-plugins-good was updated to version 1.16.3 (bsc#1181255):

  - deinterlace: on-the-fly renegotiation

  - flacenc: Pass audio info from set_format() to query_total_samples()
       explicitly

  - flacparse: fix broken reordering of flac metadata

  - jack: Use jack_free(3) to release ports

  - jpegdec: check buffer size before dereferencing

  - pulse: fix discovery of newly added devices

  - qtdemux fuzzing fixes

  - qtdemux: Add &#x27 mp3 &#x27  fourcc that VLC s ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'gstreamer, ' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "gstreamer", rpm: "gstreamer~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-debuginfo", rpm: "gstreamer-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-debugsource", rpm: "gstreamer-debugsource~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-devel", rpm: "gstreamer-devel~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-doc", rpm: "gstreamer-doc~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base", rpm: "gstreamer-plugins-base~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-debuginfo", rpm: "gstreamer-plugins-base-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-debugsource", rpm: "gstreamer-plugins-base-debugsource~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-devel", rpm: "gstreamer-plugins-base-devel~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-doc", rpm: "gstreamer-plugins-base-doc~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good", rpm: "gstreamer-plugins-good~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-debuginfo", rpm: "gstreamer-plugins-good-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-debugsource", rpm: "gstreamer-plugins-good-debugsource~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-doc", rpm: "gstreamer-plugins-good-doc~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra", rpm: "gstreamer-plugins-good-extra~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra-debuginfo", rpm: "gstreamer-plugins-good-extra-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-gtk", rpm: "gstreamer-plugins-good-gtk~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-gtk-debuginfo", rpm: "gstreamer-plugins-good-gtk-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack", rpm: "gstreamer-plugins-good-jack~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack-debuginfo", rpm: "gstreamer-plugins-good-jack-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-qtqml", rpm: "gstreamer-plugins-good-qtqml~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-qtqml-debuginfo", rpm: "gstreamer-plugins-good-qtqml-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-ugly", rpm: "gstreamer-plugins-ugly~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-ugly-debuginfo", rpm: "gstreamer-plugins-ugly-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-ugly-debugsource", rpm: "gstreamer-plugins-ugly-debugsource~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-ugly-doc", rpm: "gstreamer-plugins-ugly-doc~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-utils", rpm: "gstreamer-utils~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-utils-debuginfo", rpm: "gstreamer-utils-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstallocators-1_0-0", rpm: "libgstallocators-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstallocators-1_0-0-debuginfo", rpm: "libgstallocators-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0", rpm: "libgstapp-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0-debuginfo", rpm: "libgstapp-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0", rpm: "libgstaudio-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0-debuginfo", rpm: "libgstaudio-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstfft-1_0-0", rpm: "libgstfft-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstfft-1_0-0-debuginfo", rpm: "libgstfft-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0", rpm: "libgstgl-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0-debuginfo", rpm: "libgstgl-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0", rpm: "libgstpbutils-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0-debuginfo", rpm: "libgstpbutils-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstreamer-1_0-0", rpm: "libgstreamer-1_0-0~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstreamer-1_0-0-debuginfo", rpm: "libgstreamer-1_0-0-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstriff-1_0-0", rpm: "libgstriff-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstriff-1_0-0-debuginfo", rpm: "libgstriff-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtp-1_0-0", rpm: "libgstrtp-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtp-1_0-0-debuginfo", rpm: "libgstrtp-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtsp-1_0-0", rpm: "libgstrtsp-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtsp-1_0-0-debuginfo", rpm: "libgstrtsp-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsdp-1_0-0", rpm: "libgstsdp-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsdp-1_0-0-debuginfo", rpm: "libgstsdp-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0", rpm: "libgsttag-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0-debuginfo", rpm: "libgsttag-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0", rpm: "libgstvideo-1_0-0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0-debuginfo", rpm: "libgstvideo-1_0-0-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Gst-1_0", rpm: "typelib-1_0-Gst-1_0~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstAllocators-1_0", rpm: "typelib-1_0-GstAllocators-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstApp-1_0", rpm: "typelib-1_0-GstApp-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstAudio-1_0", rpm: "typelib-1_0-GstAudio-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstGL-1_0", rpm: "typelib-1_0-GstGL-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstPbutils-1_0", rpm: "typelib-1_0-GstPbutils-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstRtp-1_0", rpm: "typelib-1_0-GstRtp-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstRtsp-1_0", rpm: "typelib-1_0-GstRtsp-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstSdp-1_0", rpm: "typelib-1_0-GstSdp-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstTag-1_0", rpm: "typelib-1_0-GstTag-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstVideo-1_0", rpm: "typelib-1_0-GstVideo-1_0~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-lang", rpm: "gstreamer-lang~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-lang", rpm: "gstreamer-plugins-base-lang~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-lang", rpm: "gstreamer-plugins-good-lang~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-ugly-lang", rpm: "gstreamer-plugins-ugly-lang~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-32bit", rpm: "gstreamer-32bit~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-32bit-debuginfo", rpm: "gstreamer-32bit-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-32bit", rpm: "gstreamer-plugins-base-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-32bit-debuginfo", rpm: "gstreamer-plugins-base-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-devel-32bit", rpm: "gstreamer-plugins-base-devel-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-32bit", rpm: "gstreamer-plugins-good-32bit~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-32bit-debuginfo", rpm: "gstreamer-plugins-good-32bit-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra-32bit", rpm: "gstreamer-plugins-good-extra-32bit~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra-32bit-debuginfo", rpm: "gstreamer-plugins-good-extra-32bit-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack-32bit", rpm: "gstreamer-plugins-good-jack-32bit~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack-32bit-debuginfo", rpm: "gstreamer-plugins-good-jack-32bit-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-ugly-32bit", rpm: "gstreamer-plugins-ugly-32bit~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-ugly-32bit-debuginfo", rpm: "gstreamer-plugins-ugly-32bit-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstallocators-1_0-0-32bit", rpm: "libgstallocators-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstallocators-1_0-0-32bit-debuginfo", rpm: "libgstallocators-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0-32bit", rpm: "libgstapp-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0-32bit-debuginfo", rpm: "libgstapp-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0-32bit", rpm: "libgstaudio-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0-32bit-debuginfo", rpm: "libgstaudio-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstfft-1_0-0-32bit", rpm: "libgstfft-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstfft-1_0-0-32bit-debuginfo", rpm: "libgstfft-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0-32bit", rpm: "libgstgl-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0-32bit-debuginfo", rpm: "libgstgl-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0-32bit", rpm: "libgstpbutils-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0-32bit-debuginfo", rpm: "libgstpbutils-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstreamer-1_0-0-32bit", rpm: "libgstreamer-1_0-0-32bit~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstreamer-1_0-0-32bit-debuginfo", rpm: "libgstreamer-1_0-0-32bit-debuginfo~1.16.3~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstriff-1_0-0-32bit", rpm: "libgstriff-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstriff-1_0-0-32bit-debuginfo", rpm: "libgstriff-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtp-1_0-0-32bit", rpm: "libgstrtp-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtp-1_0-0-32bit-debuginfo", rpm: "libgstrtp-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtsp-1_0-0-32bit", rpm: "libgstrtsp-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtsp-1_0-0-32bit-debuginfo", rpm: "libgstrtsp-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsdp-1_0-0-32bit", rpm: "libgstsdp-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsdp-1_0-0-32bit-debuginfo", rpm: "libgstsdp-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0-32bit", rpm: "libgsttag-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0-32bit-debuginfo", rpm: "libgsttag-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0-32bit", rpm: "libgstvideo-1_0-0-32bit~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0-32bit-debuginfo", rpm: "libgstvideo-1_0-0-32bit-debuginfo~1.16.3~4.3.1", rls: "openSUSELeap15.3" ) )){
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

