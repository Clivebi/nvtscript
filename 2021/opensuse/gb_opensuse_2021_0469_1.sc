if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853740" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2020-27840", "CVE-2021-20277" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 19:46:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:27 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for ldb (openSUSE-SU-2021:0469-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0469-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QLNA72I7E6KKMIQOHXHYRPDYGMW5KH4K" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ldb'
  package(s) announced via the openSUSE-SU-2021:0469-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ldb fixes the following issues:

  - CVE-2020-27840: Fixed an unauthenticated remote heap corruption via bad
       DNs (bsc#1183572).

  - CVE-2021-20277: Fixed an out of bounds read in ldb_handler_fold
       (bsc#1183574).

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'ldb' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "ldb-debugsource", rpm: "ldb-debugsource~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ldb-tools", rpm: "ldb-tools~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ldb-tools-debuginfo", rpm: "ldb-tools-debuginfo~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb2", rpm: "libldb2~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb2-debuginfo", rpm: "libldb2-debuginfo~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb", rpm: "python3-ldb~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-debuginfo", rpm: "python3-ldb-debuginfo~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-devel", rpm: "python3-ldb-devel~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb2-32bit", rpm: "libldb2-32bit~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb2-32bit-debuginfo", rpm: "libldb2-32bit-debuginfo~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-32bit", rpm: "python3-ldb-32bit~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-32bit-debuginfo", rpm: "python3-ldb-32bit-debuginfo~2.0.12~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
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

