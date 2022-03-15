if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853902" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2021-33195", "CVE-2021-33196", "CVE-2021-33197", "CVE-2021-33198" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-11 18:43:00 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 03:01:18 +0000 (Fri, 02 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for go1.15 (openSUSE-SU-2021:0950-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0950-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SGO7YQOALHD4E75OV7S4WAPP2UR3AXKT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'go1.15'
  package(s) announced via the openSUSE-SU-2021:0950-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for go1.15 fixes the following issues:

     Update to 1.15.13.

     Includes these security fixes

  - CVE-2021-33195: net: Lookup functions may return invalid host names
       (bsc#1187443).

  - CVE-2021-33196: archive/zip: malformed archive may cause panic or memory
       exhaustion (bsc#1186622).

  - CVE-2021-33197: net/http/httputil: ReverseProxy forwards Connection
       headers if first one is empty (bsc#1187444)

  - CVE-2021-33198: math/big: (*Rat).SetString with
       '1.770p02041010010011001001' crashes with 'makeslice: len out of
  range'
       (bsc#1187445).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'go1.15' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "go1.15", rpm: "go1.15~1.15.13~lp152.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-doc", rpm: "go1.15-doc~1.15.13~lp152.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-race", rpm: "go1.15-race~1.15.13~lp152.20.1", rls: "openSUSELeap15.2" ) )){
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

