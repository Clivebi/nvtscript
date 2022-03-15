if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854149" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-22930", "CVE-2021-22931", "CVE-2021-22939", "CVE-2021-3672" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 13:54:00 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-09-08 01:01:57 +0000 (Wed, 08 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for nodejs10 (openSUSE-SU-2021:1239-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1239-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XVSODU3IBFQTSXJDK3YGWSPCAZNRBOB3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs10'
  package(s) announced via the openSUSE-SU-2021:1239-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs10 fixes the following issues:

  - CVE-2021-3672: Fixed missing input validation on hostnames (bsc#1188881).

  - CVE-2021-22930: Fixed use after free on close http2 on stream canceling
       (bsc#1188917).

  - CVE-2021-22939: Fixed incomplete validation of rejectUnauthorized
       parameter (bsc#1189369).

  - CVE-2021-22931: Fixed improper handling of untypical characters in
       domain names (bsc#1189370).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'nodejs10' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs10", rpm: "nodejs10~10.24.1~lp152.2.18.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debuginfo", rpm: "nodejs10-debuginfo~10.24.1~lp152.2.18.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debugsource", rpm: "nodejs10-debugsource~10.24.1~lp152.2.18.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-devel", rpm: "nodejs10-devel~10.24.1~lp152.2.18.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm10", rpm: "npm10~10.24.1~lp152.2.18.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-docs", rpm: "nodejs10-docs~10.24.1~lp152.2.18.1", rls: "openSUSELeap15.2" ) )){
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
