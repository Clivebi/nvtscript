if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853659" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-26215" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-03 15:59:00 +0000 (Thu, 03 Dec 2020)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:08 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for python-notebook (openSUSE-SU-2021:0024-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0024-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T2R7EJ2EM5E7MLFSQTMZGFVV45CYMONR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-notebook'
  package(s) announced via the openSUSE-SU-2021:0024-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-notebook fixes the following issue:

  - CVE-2020-26215: Fixed an open redirect vulnerability (boo#1180458)." );
	script_tag( name: "affected", value: "'python-notebook' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "jupyter-notebook", rpm: "jupyter-notebook~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jupyter-notebook-doc", rpm: "jupyter-notebook-doc~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jupyter-notebook-lang", rpm: "jupyter-notebook-lang~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jupyter-notebook-latex", rpm: "jupyter-notebook-latex~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-notebook", rpm: "python2-notebook~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-notebook-lang", rpm: "python2-notebook-lang~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-notebook", rpm: "python3-notebook~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-notebook-lang", rpm: "python3-notebook-lang~5.7.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

