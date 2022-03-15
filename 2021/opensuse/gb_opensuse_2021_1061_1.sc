if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853991" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-7774", "CVE-2021-22918", "CVE-2021-23362", "CVE-2021-27290", "CVE-2021-3449", "CVE-2021-3450" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-20 03:02:15 +0000 (Tue, 20 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for nodejs10 (openSUSE-SU-2021:1061-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1061-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SR22RRAXGLDTLSDJRAQ4O3Q67G2PNEGJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs10'
  package(s) announced via the openSUSE-SU-2021:1061-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs10 fixes the following issues:

     Update nodejs10 to 10.24.1.

     Including fixes for

  - CVE-2021-22918: libuv upgrade - Out of bounds read (bsc#1187973)

  - CVE-2021-27290: ssri Regular Expression Denial of Service (bsc#1187976)

  - CVE-2021-23362: hosted-git-info Regular Expression Denial of Service
       (bsc#1187977)

  - CVE-2020-7774: y18n Prototype Pollution (bsc#1184450)

  - CVE-2021-3450: OpenSSL - CA certificate check bypass with
       X509_V_FLAG_X509_STRICT (bsc#1183851)

  - CVE-2021-3449: OpenSSL - NULL pointer deref in signature_algorithms
       processing (bsc#1183852)

  - reduce memory footprint of test-worker-stdio (bsc#1183155)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'nodejs10' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs10", rpm: "nodejs10~10.24.1~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debuginfo", rpm: "nodejs10-debuginfo~10.24.1~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debugsource", rpm: "nodejs10-debugsource~10.24.1~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-devel", rpm: "nodejs10-devel~10.24.1~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm10", rpm: "npm10~10.24.1~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-docs", rpm: "nodejs10-docs~10.24.1~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
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
