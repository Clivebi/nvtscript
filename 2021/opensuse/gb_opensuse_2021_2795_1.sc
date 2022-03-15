if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854086" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-21704" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-21 03:01:49 +0000 (Sat, 21 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for php7 (openSUSE-SU-2021:2795-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2795-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7OI533FKAZPJKSHOKRDDHYZBMHCKP25U" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7'
  package(s) announced via the openSUSE-SU-2021:2795-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for php7 fixes the following issues:

  - CVE-2021-21704: Fixed security issues in pdo_firebase module
       (bsc#1188035)." );
	script_tag( name: "affected", value: "'php7' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "php7-wddx", rpm: "php7-wddx~7.2.5~4.79.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-wddx-debuginfo", rpm: "php7-wddx-debuginfo~7.2.5~4.79.1", rls: "openSUSELeap15.3" ) )){
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

