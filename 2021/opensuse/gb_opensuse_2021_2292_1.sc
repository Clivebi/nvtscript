if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853910" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2020-35512" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-08 21:15:00 +0000 (Mon, 08 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:02:35 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for dbus-1 (openSUSE-SU-2021:2292-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2292-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YPWMH7OQGRFBQ2ZFL5Z3HCT443A45EIB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dbus-1'
  package(s) announced via the openSUSE-SU-2021:2292-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dbus-1 fixes the following issues:

  - CVE-2020-35512: Fixed a use-after-free or potential undefined behaviour
       caused by shared UID&#x27 s (bsc#1187105)


  Special Instructions and Notes:

     Please reboot the system after installing this update." );
	script_tag( name: "affected", value: "'dbus-1' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "dbus-1", rpm: "dbus-1~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-debuginfo", rpm: "dbus-1-debuginfo~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-debugsource", rpm: "dbus-1-debugsource~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-devel", rpm: "dbus-1-devel~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11", rpm: "dbus-1-x11~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11-debuginfo", rpm: "dbus-1-x11-debuginfo~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11-debugsource", rpm: "dbus-1-x11-debugsource~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3", rpm: "libdbus-1-3~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-debuginfo", rpm: "libdbus-1-3-debuginfo~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-32bit-debuginfo", rpm: "dbus-1-32bit-debuginfo~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-devel-32bit", rpm: "dbus-1-devel-32bit~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-32bit", rpm: "libdbus-1-3-32bit~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-32bit-debuginfo", rpm: "libdbus-1-3-32bit-debuginfo~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-devel-doc", rpm: "dbus-1-devel-doc~1.12.2~8.6.1", rls: "openSUSELeap15.3" ) )){
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

