if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853904" );
	script_version( "2021-07-06T12:11:22+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 03:01:16 +0000 (Tue, 06 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for clamav-database (openSUSE-SU-2021:2242-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2242-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/E3NGPEVWSBN2EXCYIIBZDK6OLX2KGSLU" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav-database'
  package(s) announced via the openSUSE-SU-2021:2242-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for clamav-database fixes the following issues:

     Changes in clamav-database:

  - database refresh on 2021-07-05 (bsc#1084929)" );
	script_tag( name: "affected", value: "'clamav-database' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "clamav-database-202107050018", rpm: "clamav-database-202107050018~3.480.1", rls: "openSUSELeap15.3" ) )){
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

