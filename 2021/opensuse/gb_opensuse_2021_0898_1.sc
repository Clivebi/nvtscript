if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853873" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-30554", "CVE-2021-30555", "CVE-2021-30556", "CVE-2021-30557" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-18 03:15:00 +0000 (Sun, 18 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-22 03:03:34 +0000 (Tue, 22 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2021:0898-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0898-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JRQS6E56EGURN6VSX6LRCTP5WHICGNXR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:0898-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

     Chromium 91.0.4472.114 (boo#1187481)

  * CVE-2021-30554: Use after free in WebGL

  * CVE-2021-30555: Use after free in Sharing

  * CVE-2021-30556: Use after free in WebAudio

  * CVE-2021-30557: Use after free in TabGroups

     Chromium 91.0.4472.106

  * Fix use-after-free in SendTabToSelfSubMenuModel

  * Destroy system-token NSSCertDatabase on the IO thread" );
	script_tag( name: "affected", value: "'chromium' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~91.0.4472.114~lp152.2.107.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~91.0.4472.114~lp152.2.107.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~91.0.4472.114~lp152.2.107.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~91.0.4472.114~lp152.2.107.1", rls: "openSUSELeap15.2" ) )){
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

