if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851351" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-06-23 05:24:29 +0200 (Thu, 23 Jun 2016)" );
	script_cve_id( "CVE-2016-3941", "CVE-2016-5108" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for vlc (openSUSE-SU-2016:1651-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vlc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for vlc to version 2.1.6 fixes the following issues:

  These CVE were fixed:

  - CVE-2016-5108: Reject invalid QuickTime IMA files (boo#984382).

  - CVE-2016-3941: Heap overflow in processing wav files (boo#973354).

  These security issues without were fixed:

  - Fix heap overflow in decomp stream filter.

  - Fix buffer overflow in updater.

  - Fix potential buffer overflow in schroedinger encoder.

  - Fix null-pointer dereference in DMO decoder.

  - Fix buffer overflow in parsing of string boxes in mp4 demuxer.

  - Fix SRTP integer overflow.

  - Fix potential crash in zip access.

  - Fix read overflow in Ogg demuxer." );
	script_tag( name: "affected", value: "vlc on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1651-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "libvlc5", rpm: "libvlc5~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlc5-debuginfo", rpm: "libvlc5-debuginfo~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlccore7", rpm: "libvlccore7~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlccore7-debuginfo", rpm: "libvlccore7-debuginfo~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc", rpm: "vlc~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-debuginfo", rpm: "vlc-debuginfo~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-debugsource", rpm: "vlc-debugsource~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-devel", rpm: "vlc-devel~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-gnome", rpm: "vlc-gnome~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-gnome-debuginfo", rpm: "vlc-gnome-debuginfo~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX", rpm: "vlc-noX~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX-debuginfo", rpm: "vlc-noX-debuginfo~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-qt", rpm: "vlc-qt~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-qt-debuginfo", rpm: "vlc-qt-debuginfo~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX-lang", rpm: "vlc-noX-lang~2.1.6~2.10.1", rls: "openSUSE13.2" ) )){
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

