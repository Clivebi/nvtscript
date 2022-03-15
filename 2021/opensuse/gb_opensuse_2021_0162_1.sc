if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853623" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-3181" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-17 17:08:00 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:15 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for mutt (openSUSE-SU-2021:0162-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0162-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TXFLXGSUQPBN7TELGSNJZPFUX7KMTSBT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mutt'
  package(s) announced via the openSUSE-SU-2021:0162-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mutt fixes the following issue:

  - CVE-2021-3181: Fixed a memory leak in recipient parsing (bsc#1181221).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'mutt' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "mutt-doc", rpm: "mutt-doc~1.10.1~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mutt-lang", rpm: "mutt-lang~1.10.1~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mutt", rpm: "mutt~1.10.1~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mutt-debuginfo", rpm: "mutt-debuginfo~1.10.1~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mutt-debugsource", rpm: "mutt-debugsource~1.10.1~lp152.3.15.1", rls: "openSUSELeap15.2" ) )){
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

