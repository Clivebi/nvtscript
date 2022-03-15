if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853541" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-14355" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:01:25 +0000 (Tue, 03 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for spice-gtk (openSUSE-SU-2020:1803-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1803-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00000.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-gtk'
  package(s) announced via the openSUSE-SU-2020:1803-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spice-gtk fixes the following issues:

  - CVE-2020-14355: Fixed multiple buffer overflow vulnerabilities in QUIC
  image decoding (bsc#1177158).

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1803=1" );
	script_tag( name: "affected", value: "'spice-gtk' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-lang", rpm: "spice-gtk-lang~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-2_0-8", rpm: "libspice-client-glib-2_0-8~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-2_0-8-debuginfo", rpm: "libspice-client-glib-2_0-8-debuginfo~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-helper", rpm: "libspice-client-glib-helper~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-helper-debuginfo", rpm: "libspice-client-glib-helper-debuginfo~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-gtk-3_0-5", rpm: "libspice-client-gtk-3_0-5~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-gtk-3_0-5-debuginfo", rpm: "libspice-client-gtk-3_0-5-debuginfo~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk", rpm: "spice-gtk~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-debuginfo", rpm: "spice-gtk-debuginfo~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-debugsource", rpm: "spice-gtk-debugsource~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-devel", rpm: "spice-gtk-devel~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-SpiceClientGlib-2_0", rpm: "typelib-1_0-SpiceClientGlib-2_0~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-SpiceClientGtk-3_0", rpm: "typelib-1_0-SpiceClientGtk-3_0~0.37~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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
