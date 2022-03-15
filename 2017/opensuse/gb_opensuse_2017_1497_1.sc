if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851563" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-07 06:48:00 +0200 (Wed, 07 Jun 2017)" );
	script_cve_id( "CVE-2017-7178", "CVE-2017-9031" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for deluge (openSUSE-SU-2017:1497-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'deluge'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for deluge fixes two security
  issues: - CVE-2017-9031: A remote attacker may have used a directory traversal
  vulnerability in the web interface (bsc#1039815) - CVE-2017-7178: A remote
  attacher could have exploited a CSRF vulnerability to trick a logged-in user to
  perform actions in the WebUI (bsc#1039958) In addition, deluge was updated to
  1.3.15 with the following fixes and changes: - Core: Fix issues with displaying
  libtorrent-rasterbar single proxy. - Core: Fix libtorrent-rasterbar 1.2 trackers
  crashing Deluge UIs. - Core: Fix an error in torrent priorities causing file
  priority mismatch in UIs. - GtkUI: Fix column sort state not saved in Thinclient
  mode. - GtkUI: Fix a connection manager error with malformed ip. - GtkUI: Rename
  SystemTray/Indicator 'Pause/Resume All' to 'Pause/Resume Session'. - GtkUI:
  Workaround libtorrent-rasterbar single proxy by greying out unused proxy types.

  - Notification Plugin: Fix webui passing string for int port value. - AutoAdd
  Plugin: Add WebUI preferences page detailing lack of configuration via WebUI. -
  Label Plugin: Add WebUI preferences page detailing how to configure plugin. -
  Core: Fix 'Too many files open' errors. - Core: Add support for python-GeoIP for
  use with libtorrent 1.1. - Core: Fix a single proxy entry being overwritten
  resulting in no proxy set. - UI: Add the tracker_status translation to UIs. -
  GtkUI: Strip whitespace from infohash before checks. - GtkUI: Add a missed
  feature autofill infohash entry from clipboard. - WebUI: Backport bind interface
  option for server. - ConsoleUI: Fix a decode error comparing non-ascii (str)
  torrent names. - AutoAdd Plugin: Fixes for splitting magnets from file. - Remove
  the duplicate magnet extension when splitting. - Remove
  deluge-libtorrent-1.1-geoip.patch: fixed upstream." );
	script_tag( name: "affected", value: "deluge on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:1497-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "deluge", rpm: "deluge~1.3.15~3.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "deluge-lang", rpm: "deluge-lang~1.3.15~3.3.1", rls: "openSUSELeap42.2" ) )){
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

