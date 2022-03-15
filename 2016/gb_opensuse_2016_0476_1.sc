if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851205" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-02-17 06:28:02 +0100 (Wed, 17 Feb 2016)" );
	script_cve_id( "CVE-2015-5949" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for vlc (openSUSE-SU-2016:0476-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vlc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for vlc fixes the following issues:

  - CVE-2015-5949: Remote attackers could have caused a denial of service
  (crash) and possibly execute arbitrary code via a crafted 3GP file
  (boo#965227)" );
	script_tag( name: "affected", value: "vlc on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0476-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "libvlc5", rpm: "libvlc5~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlc5-debuginfo", rpm: "libvlc5-debuginfo~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlccore8", rpm: "libvlccore8~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvlccore8-debuginfo", rpm: "libvlccore8-debuginfo~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc", rpm: "vlc~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-debuginfo", rpm: "vlc-debuginfo~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-debugsource", rpm: "vlc-debugsource~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-devel", rpm: "vlc-devel~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-gnome", rpm: "vlc-gnome~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-gnome-debuginfo", rpm: "vlc-gnome-debuginfo~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX", rpm: "vlc-noX~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX-debuginfo", rpm: "vlc-noX-debuginfo~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-qt", rpm: "vlc-qt~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-qt-debuginfo", rpm: "vlc-qt-debuginfo~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vlc-noX-lang", rpm: "vlc-noX-lang~2.2.1~24.1", rls: "openSUSELeap42.1" ) )){
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

