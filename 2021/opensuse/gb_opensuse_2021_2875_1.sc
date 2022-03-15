if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854125" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2021-22930", "CVE-2021-22931", "CVE-2021-22939", "CVE-2021-22940", "CVE-2021-3672" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 13:54:00 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-31 01:01:59 +0000 (Tue, 31 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for nodejs12 (openSUSE-SU-2021:2875-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2875-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HHIBOQVFGTSNZKZ3C7TDCN35RIGH22D4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs12'
  package(s) announced via the openSUSE-SU-2021:2875-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs12 fixes the following issues:

     Update to 12.22.5:

  - CVE-2021-3672/CVE-2021-22931: Improper handling of untypical characters
       in domain names (bsc#1189370, bsc#1188881)

  - CVE-2021-22940: Use after free on close http2 on stream canceling
       (bsc#1189368)

  - CVE-2021-22939: Incomplete validation of rejectUnauthorized parameter
       (bsc#1189369)

  - CVE-2021-22930: http2: fixes use after free on close http2 on stream
       canceling (bsc#1188917)" );
	script_tag( name: "affected", value: "'nodejs12' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs12", rpm: "nodejs12~12.22.5~4.19.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debuginfo", rpm: "nodejs12-debuginfo~12.22.5~4.19.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debugsource", rpm: "nodejs12-debugsource~12.22.5~4.19.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-devel", rpm: "nodejs12-devel~12.22.5~4.19.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm12", rpm: "npm12~12.22.5~4.19.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-docs", rpm: "nodejs12-docs~12.22.5~4.19.1", rls: "openSUSELeap15.3" ) )){
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

