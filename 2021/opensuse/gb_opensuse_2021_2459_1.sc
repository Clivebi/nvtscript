if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854014" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-3588" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 16:15:00 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-23 03:01:41 +0000 (Fri, 23 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for bluez (openSUSE-SU-2021:2459-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2459-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FD7KE3RMFCUKN7TQCYXDCNJGFVIORKJL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bluez'
  package(s) announced via the openSUSE-SU-2021:2459-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bluez fixes the following issues:

  - CVE-2021-3588: Fixed a missing bounds checks inside cli_feat_read_cb()
       function in src/gatt-database.c (bsc#1187165)" );
	script_tag( name: "affected", value: "'bluez' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "bluez", rpm: "bluez~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-cups", rpm: "bluez-cups~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-cups-debuginfo", rpm: "bluez-cups-debuginfo~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-debuginfo", rpm: "bluez-debuginfo~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-debugsource", rpm: "bluez-debugsource~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-deprecated", rpm: "bluez-deprecated~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-deprecated-debuginfo", rpm: "bluez-deprecated-debuginfo~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-devel", rpm: "bluez-devel~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-test", rpm: "bluez-test~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-test-debuginfo", rpm: "bluez-test-debuginfo~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3", rpm: "libbluetooth3~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3-debuginfo", rpm: "libbluetooth3-debuginfo~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-devel-32bit", rpm: "bluez-devel-32bit~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3-32bit", rpm: "libbluetooth3-32bit~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3-32bit-debuginfo", rpm: "libbluetooth3-32bit-debuginfo~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-auto-enable-devices", rpm: "bluez-auto-enable-devices~5.55~3.6.1", rls: "openSUSELeap15.3" ) )){
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

