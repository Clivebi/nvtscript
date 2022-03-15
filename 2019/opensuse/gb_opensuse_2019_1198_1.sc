if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852417" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_cve_id( "CVE-2016-9918" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-12 13:29:00 +0000 (Fri, 12 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-13 02:00:53 +0000 (Sat, 13 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for bluez (openSUSE-SU-2019:1198-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1198-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00054.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bluez'
  package(s) announced via the openSUSE-SU-2019:1198-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bluez fixes the following issues:

  Security issue fixed:

  - CVE-2016-9918: Fixed an out-of-bound read in the packet_hexdump function
  (bsc#1015173)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1198=1" );
	script_tag( name: "affected", value: "'bluez' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "bluez", rpm: "bluez~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-cups", rpm: "bluez-cups~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-cups-debuginfo", rpm: "bluez-cups-debuginfo~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-debuginfo", rpm: "bluez-debuginfo~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-debugsource", rpm: "bluez-debugsource~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-devel", rpm: "bluez-devel~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-test", rpm: "bluez-test~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-test-debuginfo", rpm: "bluez-test-debuginfo~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3", rpm: "libbluetooth3~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3-debuginfo", rpm: "libbluetooth3-debuginfo~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-auto-enable-devices", rpm: "bluez-auto-enable-devices~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-devel-32bit", rpm: "bluez-devel-32bit~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3-32bit", rpm: "libbluetooth3-32bit~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3-32bit-debuginfo", rpm: "libbluetooth3-32bit-debuginfo~5.48~lp150.4.10.1", rls: "openSUSELeap15.0" ) )){
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
