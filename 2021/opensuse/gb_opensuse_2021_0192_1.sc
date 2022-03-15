if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853613" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-3114", "CVE-2021-3115" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 15:44:00 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:56:54 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for go1.15 (openSUSE-SU-2021:0192-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0192-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DLSYUO4X4LW4VZTYIOWDRLII23FZ4LSP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'go1.15'
  package(s) announced via the openSUSE-SU-2021:0192-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for go1.15 fixes the following issues:

     Go was updated to version 1.15.7 (bsc#1175132).

     Security issues fixed:

  - CVE-2021-3114: Fixed incorrect operations on the P-224 curve in
       crypto/elliptic (bsc#1181145).

  - CVE-2021-3115: Fixed a potential arbitrary code execution in the build
       process (bsc#1181146).

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
	if(!isnull( res = isrpmvuln( pkg: "go1.15", rpm: "go1.15~1.15.7~lp152.8.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-doc", rpm: "go1.15-doc~1.15.7~lp152.8.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-race", rpm: "go1.15-race~1.15.7~lp152.8.1", rls: "openSUSELeap15.2" ) )){
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

