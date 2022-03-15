if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854142" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-3497", "CVE-2021-3498" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-27 16:48:00 +0000 (Tue, 27 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-09-06 01:01:46 +0000 (Mon, 06 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for gstreamer-plugins-good (openSUSE-SU-2021:1230-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1230-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GU3E72N7AIZNV6RLT3OM7V74BRCXVX4R" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer-plugins-good'
  package(s) announced via the openSUSE-SU-2021:1230-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gstreamer-plugins-good fixes the following issues:

  - CVE-2021-3498: Matroskademux: initialize track context out parameter to
       NULL before parsing (bsc#1184735).

  - CVE-2021-3497: Matroskademux: Fix extraction of multichannel WavPack
       (bsc#1184739).

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'gstreamer-plugins-good' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good", rpm: "gstreamer-plugins-good~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-debuginfo", rpm: "gstreamer-plugins-good-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-debugsource", rpm: "gstreamer-plugins-good-debugsource~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-doc", rpm: "gstreamer-plugins-good-doc~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra", rpm: "gstreamer-plugins-good-extra~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra-debuginfo", rpm: "gstreamer-plugins-good-extra-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-gtk", rpm: "gstreamer-plugins-good-gtk~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-gtk-debuginfo", rpm: "gstreamer-plugins-good-gtk-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack", rpm: "gstreamer-plugins-good-jack~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack-debuginfo", rpm: "gstreamer-plugins-good-jack-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-qtqml", rpm: "gstreamer-plugins-good-qtqml~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-qtqml-debuginfo", rpm: "gstreamer-plugins-good-qtqml-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-32bit", rpm: "gstreamer-plugins-good-32bit~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-32bit-debuginfo", rpm: "gstreamer-plugins-good-32bit-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra-32bit", rpm: "gstreamer-plugins-good-extra-32bit~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-extra-32bit-debuginfo", rpm: "gstreamer-plugins-good-extra-32bit-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack-32bit", rpm: "gstreamer-plugins-good-jack-32bit~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-jack-32bit-debuginfo", rpm: "gstreamer-plugins-good-jack-32bit-debuginfo~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-good-lang", rpm: "gstreamer-plugins-good-lang~1.16.3~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
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

