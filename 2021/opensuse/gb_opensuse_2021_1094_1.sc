if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854037" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-13645" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-22 14:47:00 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-08-07 03:01:38 +0000 (Sat, 07 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for balsa (openSUSE-SU-2021:1094-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1094-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/42QNVR5Y3Z3YQLA2G7H66ZAGRYHVNWHT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'balsa'
  package(s) announced via the openSUSE-SU-2021:1094-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for balsa fixes the following issues:

     Update to version 2.6.1

  - CVE-2020-13645: fix server identity verification (boo#1172460)" );
	script_tag( name: "affected", value: "'balsa' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "balsa-lang", rpm: "balsa-lang~2.6.1~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "balsa", rpm: "balsa~2.6.1~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "balsa-debuginfo", rpm: "balsa-debuginfo~2.6.1~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "balsa-debugsource", rpm: "balsa-debugsource~2.6.1~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

