if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852203" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_cve_id( "CVE-2018-19443" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-20 01:25:00 +0000 (Thu, 20 Dec 2018)" );
	script_tag( name: "creation_date", value: "2018-12-23 04:00:51 +0100 (Sun, 23 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for tryton (openSUSE-SU-2018:4242-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:4242-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00056.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tryton'
  package(s) announced via the openSUSE-SU-2018:4242-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tryton to version 4.2.19 fixes the following issues:

  Security issue fixed:

  - CVE-2018-19443: Fixed an information leakage by attempting to initiate an
  unencrypted connection, which would fail eventually, but might leak
  session information of the user (boo#1117105)

  This update also contains newer versions of tryton related packages with
  general bug fixes and updates:

  - trytond 4.2.17

  - trytond_account 4.2.10

  - trytond_account_invoice 4.2.7

  - trytond_purchase_request 4.2.4

  - trytond_stock 4.2.8

  - trytond_stock_supply 4.2.3

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1588=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1588=1" );
	script_tag( name: "affected", value: "tryton on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "tryton", rpm: "tryton~4.2.19~lp150.2.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trytond", rpm: "trytond~4.2.17~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trytond_account", rpm: "trytond_account~4.2.10~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trytond_account_invoice", rpm: "trytond_account_invoice~4.2.7~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trytond_purchase_request", rpm: "trytond_purchase_request~4.2.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trytond_stock", rpm: "trytond_stock~4.2.8~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "trytond_stock_supply", rpm: "trytond_stock_supply~4.2.3~lp150.2.7.1", rls: "openSUSELeap15.0" ) )){
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

