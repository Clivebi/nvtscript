if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853679" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-28473" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-28 15:57:00 +0000 (Thu, 28 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:49 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for python-bottle (openSUSE-SU-2021:0302-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0302-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NH4G4ACMTOHQQPWHAFALRZDCUZ5J46OZ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-bottle'
  package(s) announced via the openSUSE-SU-2021:0302-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-bottle fixes the following issues:

  - CVE-2020-28473: Fixed Web Cache Poisoning vulnerability using parameter
       cloaking (bsc#1182181).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'python-bottle' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-bottle-doc", rpm: "python-bottle-doc~0.12.13~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-bottle", rpm: "python2-bottle~0.12.13~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-bottle", rpm: "python3-bottle~0.12.13~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
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

