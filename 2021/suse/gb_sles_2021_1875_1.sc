if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1875.1" );
	script_cve_id( "CVE-2021-3185" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 21:30:00 +0000 (Wed, 03 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1875-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1875-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211875-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer-plugins-bad' package(s) announced via the SUSE-SU-2021:1875-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gstreamer-plugins-bad fixes the following issues:

CVE-2021-3185: Fixed buffer overflow in
 gst_h264_slice_parse_dec_ref_pic_marking (bsc#1181255)." );
	script_tag( name: "affected", value: "'gstreamer-plugins-bad' package(s) on HPE Helion Openstack 8, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad", rpm: "gstreamer-plugins-bad~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debuginfo", rpm: "gstreamer-plugins-bad-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debugsource", rpm: "gstreamer-plugins-bad-debugsource~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-lang", rpm: "gstreamer-plugins-bad-lang~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0", rpm: "libgstadaptivedemux-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0-debuginfo", rpm: "libgstadaptivedemux-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0", rpm: "libgstbadaudio-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0-debuginfo", rpm: "libgstbadaudio-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0", rpm: "libgstbadbase-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0-debuginfo", rpm: "libgstbadbase-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0", rpm: "libgstbadvideo-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0-debuginfo", rpm: "libgstbadvideo-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0", rpm: "libgstbasecamerabinsrc-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0-debuginfo", rpm: "libgstbasecamerabinsrc-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0", rpm: "libgstcodecparsers-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0-debuginfo", rpm: "libgstcodecparsers-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0", rpm: "libgstgl-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0-debuginfo", rpm: "libgstgl-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0", rpm: "libgstmpegts-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0-debuginfo", rpm: "libgstmpegts-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0", rpm: "libgstphotography-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0-debuginfo", rpm: "libgstphotography-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0", rpm: "libgsturidownloader-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0-debuginfo", rpm: "libgsturidownloader-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad", rpm: "gstreamer-plugins-bad~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debuginfo", rpm: "gstreamer-plugins-bad-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debugsource", rpm: "gstreamer-plugins-bad-debugsource~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-lang", rpm: "gstreamer-plugins-bad-lang~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0", rpm: "libgstadaptivedemux-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0-debuginfo", rpm: "libgstadaptivedemux-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0", rpm: "libgstbadaudio-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0-debuginfo", rpm: "libgstbadaudio-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0", rpm: "libgstbadbase-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0-debuginfo", rpm: "libgstbadbase-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0", rpm: "libgstbadvideo-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0-debuginfo", rpm: "libgstbadvideo-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0", rpm: "libgstbasecamerabinsrc-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0-debuginfo", rpm: "libgstbasecamerabinsrc-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0", rpm: "libgstcodecparsers-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0-debuginfo", rpm: "libgstcodecparsers-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0", rpm: "libgstgl-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0-debuginfo", rpm: "libgstgl-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0", rpm: "libgstmpegts-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0-debuginfo", rpm: "libgstmpegts-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0", rpm: "libgstphotography-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0-debuginfo", rpm: "libgstphotography-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0", rpm: "libgsturidownloader-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0-debuginfo", rpm: "libgsturidownloader-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad", rpm: "gstreamer-plugins-bad~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debuginfo", rpm: "gstreamer-plugins-bad-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debugsource", rpm: "gstreamer-plugins-bad-debugsource~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-lang", rpm: "gstreamer-plugins-bad-lang~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0", rpm: "libgstadaptivedemux-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0-debuginfo", rpm: "libgstadaptivedemux-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0", rpm: "libgstbadaudio-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0-debuginfo", rpm: "libgstbadaudio-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0", rpm: "libgstbadbase-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0-debuginfo", rpm: "libgstbadbase-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0", rpm: "libgstbadvideo-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0-debuginfo", rpm: "libgstbadvideo-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0", rpm: "libgstbasecamerabinsrc-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0-debuginfo", rpm: "libgstbasecamerabinsrc-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0", rpm: "libgstcodecparsers-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0-debuginfo", rpm: "libgstcodecparsers-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0", rpm: "libgstgl-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0-debuginfo", rpm: "libgstgl-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0", rpm: "libgstmpegts-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0-debuginfo", rpm: "libgstmpegts-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0", rpm: "libgstphotography-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0-debuginfo", rpm: "libgstphotography-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0", rpm: "libgsturidownloader-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0-debuginfo", rpm: "libgsturidownloader-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad", rpm: "gstreamer-plugins-bad~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debuginfo", rpm: "gstreamer-plugins-bad-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-debugsource", rpm: "gstreamer-plugins-bad-debugsource~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-bad-lang", rpm: "gstreamer-plugins-bad-lang~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0", rpm: "libgstadaptivedemux-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstadaptivedemux-1_0-0-debuginfo", rpm: "libgstadaptivedemux-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0", rpm: "libgstbadaudio-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadaudio-1_0-0-debuginfo", rpm: "libgstbadaudio-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0", rpm: "libgstbadbase-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadbase-1_0-0-debuginfo", rpm: "libgstbadbase-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0", rpm: "libgstbadvideo-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbadvideo-1_0-0-debuginfo", rpm: "libgstbadvideo-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0", rpm: "libgstbasecamerabinsrc-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-1_0-0-debuginfo", rpm: "libgstbasecamerabinsrc-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0", rpm: "libgstcodecparsers-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstcodecparsers-1_0-0-debuginfo", rpm: "libgstcodecparsers-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0", rpm: "libgstgl-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstgl-1_0-0-debuginfo", rpm: "libgstgl-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0", rpm: "libgstmpegts-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstmpegts-1_0-0-debuginfo", rpm: "libgstmpegts-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0", rpm: "libgstphotography-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-1_0-0-debuginfo", rpm: "libgstphotography-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0", rpm: "libgsturidownloader-1_0-0~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsturidownloader-1_0-0-debuginfo", rpm: "libgsturidownloader-1_0-0-debuginfo~1.8.3~18.3.5", rls: "SLES12.0SP5" ) )){
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

