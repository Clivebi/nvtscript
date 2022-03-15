if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853714" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-27225" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-18 18:22:00 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:01:21 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for eclipse (openSUSE-SU-2021:0485-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0485-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GFMJOYKYZTYC75UCIIQQRAD674LFJI3L" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'eclipse'
  package(s) announced via the openSUSE-SU-2021:0485-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for eclipse fixes the following issues:

  - CVE-2020-27225: Authenticate active help requests to the local help web
        server (bsc#1183728).

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'eclipse' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "eclipse-bootstrap-debuginfo", rpm: "eclipse-bootstrap-debuginfo~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-bootstrap-debugsource", rpm: "eclipse-bootstrap-debugsource~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-contributor-tools", rpm: "eclipse-contributor-tools~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-contributor-tools-bootstrap", rpm: "eclipse-contributor-tools-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-debuginfo", rpm: "eclipse-debuginfo~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-debugsource", rpm: "eclipse-debugsource~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-equinox-osgi", rpm: "eclipse-equinox-osgi~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-equinox-osgi-bootstrap", rpm: "eclipse-equinox-osgi-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-pde", rpm: "eclipse-pde~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-pde-bootstrap", rpm: "eclipse-pde-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-platform", rpm: "eclipse-platform~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-platform-bootstrap", rpm: "eclipse-platform-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-platform-bootstrap-debuginfo", rpm: "eclipse-platform-bootstrap-debuginfo~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-platform-debuginfo", rpm: "eclipse-platform-debuginfo~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-swt", rpm: "eclipse-swt~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-swt-bootstrap", rpm: "eclipse-swt-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-swt-bootstrap-debuginfo", rpm: "eclipse-swt-bootstrap-debuginfo~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-swt-debuginfo", rpm: "eclipse-swt-debuginfo~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-tests", rpm: "eclipse-tests~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-tests-bootstrap", rpm: "eclipse-tests-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-jdt", rpm: "eclipse-jdt~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-jdt-bootstrap", rpm: "eclipse-jdt-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-p2-discovery", rpm: "eclipse-p2-discovery~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eclipse-p2-discovery-bootstrap", rpm: "eclipse-p2-discovery-bootstrap~4.9.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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

