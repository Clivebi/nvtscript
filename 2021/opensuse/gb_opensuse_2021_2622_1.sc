if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854039" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2020-2875", "CVE-2020-2933", "CVE-2020-2934" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-08-07 03:01:40 +0000 (Sat, 07 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for mysql-connector-java (openSUSE-SU-2021:2622-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2622-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KHHGZ3MEHVZT3NYQIEG5WTISHLXRLW3D" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-connector-java'
  package(s) announced via the openSUSE-SU-2021:2622-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mysql-connector-java fixes the following issues:

  - CVE-2020-2875: Unauthenticated attacker with network access via multiple
       protocols can compromise MySQL Connectors. (bsc#1173600)

  - CVE-2020-2934: Fixed a vulnerability which could cause a partial denial
       of service of MySQL Connectors. (bsc#1173600)

  - CVE-2020-2933: Fixed a vulnerability which could allows high privileged
       attacker with network access via multiple protocols to compromise MySQL
       Connectors. (bsc#1173600)" );
	script_tag( name: "affected", value: "'mysql-connector-java' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "mysql-connector-java", rpm: "mysql-connector-java~5.1.47~3.3.1", rls: "openSUSELeap15.3" ) )){
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

