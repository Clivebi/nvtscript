if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853615" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-35458" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-21 14:28:00 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:56:56 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for hawk2 (openSUSE-SU-2021:0054-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0054-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VO5ZHH4IHE4JSXKLL5QNLXOG2AGDRLET" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hawk2'
  package(s) announced via the openSUSE-SU-2021:0054-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for hawk2 fixes the following security issue:

  - CVE-2020-35458: Fixed an insufficient input handler that could have led
       to remote code execution (bsc#1179998).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'hawk2' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "hawk2", rpm: "hawk2~2.3.0+git.1603969748.10468582~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hawk2-debuginfo", rpm: "hawk2-debuginfo~2.3.0+git.1603969748.10468582~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hawk2-debugsource", rpm: "hawk2-debugsource~2.3.0+git.1603969748.10468582~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
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

