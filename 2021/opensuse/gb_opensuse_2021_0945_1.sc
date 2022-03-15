if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853900" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-25321" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 13:56:00 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 03:01:08 +0000 (Fri, 02 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for arpwatch (openSUSE-SU-2021:0945-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0945-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y7SKTH3533HITV3EN436RULMJP2HHQND" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'arpwatch'
  package(s) announced via the openSUSE-SU-2021:0945-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for arpwatch fixes the following issues:

  - CVE-2021-25321: Fixed local privilege escalation from runtime user to
       root (bsc#1186240).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'arpwatch' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "arpwatch", rpm: "arpwatch~2.1a15~lp152.6.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "arpwatch-debuginfo", rpm: "arpwatch-debuginfo~2.1a15~lp152.6.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "arpwatch-debugsource", rpm: "arpwatch-debugsource~2.1a15~lp152.6.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "arpwatch-ethercodes-build", rpm: "arpwatch-ethercodes-build~2.1a15~lp152.6.9.1", rls: "openSUSELeap15.2" ) )){
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

