if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853612" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2021-22883", "CVE-2021-22884", "CVE-2021-23840" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:56:52 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for nodejs12 (openSUSE-SU-2021:0357-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0357-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AVDCMNKQUTQBM7Z7BU2BQ23WG4Y66BOY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs12'
  package(s) announced via the openSUSE-SU-2021:0357-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs12 fixes the following issues:

     New upstream LTS version 12.21.0:

  - CVE-2021-22883: HTTP2 &#x27 unknownProtocol&#x27  cause Denial of Service by
       resource exhaustion (bsc#1182619)

  - CVE-2021-22884: DNS rebinding in --inspect (bsc#1182620)

  - CVE-2021-23840: OpenSSL - Integer overflow in CipherUpdate (bsc#1182333)

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'nodejs12' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-docs", rpm: "nodejs12-docs~12.21.0~lp152.3.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12", rpm: "nodejs12~12.21.0~lp152.3.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debuginfo", rpm: "nodejs12-debuginfo~12.21.0~lp152.3.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debugsource", rpm: "nodejs12-debugsource~12.21.0~lp152.3.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-devel", rpm: "nodejs12-devel~12.21.0~lp152.3.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm12", rpm: "npm12~12.21.0~lp152.3.12.1", rls: "openSUSELeap15.2" ) )){
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

