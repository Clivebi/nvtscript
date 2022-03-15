if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854060" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-35515", "CVE-2021-35516", "CVE-2021-35517", "CVE-2021-36090" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-27 00:15:00 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 03:02:55 +0000 (Wed, 11 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for apache-commons-compress (openSUSE-SU-2021:1115-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1115-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YA4IHX4VRW7LQHM7JIEPOCPE46TRW6MV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache-commons-compress'
  package(s) announced via the openSUSE-SU-2021:1115-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for apache-commons-compress fixes the following issues:

  - Updated to 1.21

  - CVE-2021-35515: Fixed an infinite loop when reading a specially crafted
       7Z archive. (bsc#1188463)

  - CVE-2021-35516: Fixed an excessive memory allocation when reading a
       specially crafted 7Z archive. (bsc#1188464)

  - CVE-2021-35517: Fixed an excessive memory allocation when reading a
       specially crafted TAR archive. (bsc#1188465)

  - CVE-2021-36090: Fixed an excessive memory allocation when reading a
       specially crafted ZIP archive. (bsc#1188466)

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'apache-commons-compress' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "apache-commons-compress", rpm: "apache-commons-compress~1.21~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache-commons-compress-javadoc", rpm: "apache-commons-compress-javadoc~1.21~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

