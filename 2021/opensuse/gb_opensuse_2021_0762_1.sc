if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853826" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-18 03:15:00 +0000 (Sun, 18 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-24 03:01:05 +0000 (Mon, 24 May 2021)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2021:0762-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0762-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VXXTVK5FWZGMVLWH6O7ONOFANNOOJNWS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:0762-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

     (This is a rerelease with aarch64 enabled.)

     Chromium 90.0.4430.212 (boo#1185908)

  * CVE-2021-30506: Incorrect security UI in Web App Installs

  * CVE-2021-30507: Inappropriate implementation in Offline

  * CVE-2021-30508: Heap buffer overflow in Media Feeds

  * CVE-2021-30509: Out of bounds write in Tab Strip

  * CVE-2021-30510: Race in Aura

  * CVE-2021-30511: Out of bounds read in Tab Group

  * CVE-2021-30512: Use after free in Notifications

  * CVE-2021-30513: Type Confusion in V8

  * CVE-2021-30514: Use after free in Autofill

  * CVE-2021-30515: Use after free in File API

  * CVE-2021-30516: Heap buffer overflow in History

  * CVE-2021-30517: Type Confusion in V8

  * CVE-2021-30518: Heap buffer overflow in Reader Mode

  * CVE-2021-30519: Use after free in Payments

  * CVE-2021-30520: Use after free in Tab Strip

  - FTP support disabled at runtime by default since release 88. Chromium 91
       will remove support for ftp altogether (boo#1185496)" );
	script_tag( name: "affected", value: "'chromium' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~90.0.4430.212~lp152.2.95.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~90.0.4430.212~lp152.2.95.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~90.0.4430.212~lp152.2.95.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~90.0.4430.212~lp152.2.95.1", rls: "openSUSELeap15.2" ) )){
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

