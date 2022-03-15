if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853639" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-8293", "CVE-2020-8294", "CVE-2020-8295" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 21:02:00 +0000 (Tue, 02 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:55 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for nextcloud (openSUSE-SU-2021:0262-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0262-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RL6T5BYT4RSAM4DNXPXTDKBKHKKNDVHW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2021:0262-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nextcloud fixes the following issues:

  - nextcloud was upgraded to version 20.0.7

  - CVE-2020-8294: Fixed a missing link validation (boo#1181803)

  - CVE-2020-8295: Fixed a denial of service attack (boo#1181804)

  - CVE-2020-8293: Fixed an input validation issue (boo#1181445)" );
	script_tag( name: "affected", value: "'nextcloud' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "nextcloud", rpm: "nextcloud~20.0.7~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nextcloud-apache", rpm: "nextcloud-apache~20.0.7~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
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

