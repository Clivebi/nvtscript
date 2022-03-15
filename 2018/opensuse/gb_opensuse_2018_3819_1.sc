if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852141" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_cve_id( "CVE-2018-4022" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-28 13:35:00 +0000 (Mon, 28 Jan 2019)" );
	script_tag( name: "creation_date", value: "2018-11-21 06:04:19 +0100 (Wed, 21 Nov 2018)" );
	script_name( "openSUSE: Security Advisory for libmatroska (openSUSE-SU-2018:3819-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2018:3819-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00030.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmatroska'
  package(s) announced via the openSUSE-SU-2018:3819-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libmatroska, mkvtoolnix fixes the following issues:

  Security issue fixed:

  - CVE-2018-4022: Fixed use-after-free vulnerability that existed in the
  way MKV (matroska) file format was handled (bsc#1113709).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1432=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1432=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1432=1" );
	script_tag( name: "affected", value: "libmatroska, on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libmatroska-debugsource", rpm: "libmatroska-debugsource~1.4.9~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmatroska-devel", rpm: "libmatroska-devel~1.4.9~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmatroska6", rpm: "libmatroska6~1.4.9~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmatroska6-debuginfo", rpm: "libmatroska6-debuginfo~1.4.9~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmatroska6-32bit", rpm: "libmatroska6-32bit~1.4.9~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmatroska6-debuginfo-32bit", rpm: "libmatroska6-debuginfo-32bit~1.4.9~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix", rpm: "mkvtoolnix~28.2.0~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-debuginfo", rpm: "mkvtoolnix-debuginfo~28.2.0~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-debugsource", rpm: "mkvtoolnix-debugsource~28.2.0~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-gui", rpm: "mkvtoolnix-gui~28.2.0~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-gui-debuginfo", rpm: "mkvtoolnix-gui-debuginfo~28.2.0~8.1", rls: "openSUSELeap42.3" ) )){
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix", rpm: "mkvtoolnix~28.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-debuginfo", rpm: "mkvtoolnix-debuginfo~28.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-debugsource", rpm: "mkvtoolnix-debugsource~28.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-gui", rpm: "mkvtoolnix-gui~28.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mkvtoolnix-gui-debuginfo", rpm: "mkvtoolnix-gui-debuginfo~28.2.0~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

