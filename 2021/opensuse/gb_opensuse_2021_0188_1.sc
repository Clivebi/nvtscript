if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853688" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2019-10732" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 15:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:59 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for messagelib (openSUSE-SU-2021:0188-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0188-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UIP7JD6E7AKTOSG2IAFVY4AE7G4NZIKB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'messagelib'
  package(s) announced via the openSUSE-SU-2021:0188-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for messagelib fixes the following issues:

  - CVE-2019-10732: Prevented accidental disclosure of encrypted content
       when replying (boo#1131885)." );
	script_tag( name: "affected", value: "'messagelib' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "messagelib-lang", rpm: "messagelib-lang~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib", rpm: "messagelib~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib-debuginfo", rpm: "messagelib-debuginfo~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib-debugsource", rpm: "messagelib-debugsource~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib-devel", rpm: "messagelib-devel~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
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

