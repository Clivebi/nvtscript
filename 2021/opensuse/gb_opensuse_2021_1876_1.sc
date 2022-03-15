if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853955" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2017-18640" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-17 20:15:00 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:05:24 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for snakeyaml (openSUSE-SU-2021:1876-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1876-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FQSQDG6EG5IGZXIQVLQHFSBMALXOT6L6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'snakeyaml'
  package(s) announced via the openSUSE-SU-2021:1876-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for snakeyaml fixes the following issues:

  - Upgrade to 1.28

  - CVE-2017-18640: The Alias feature allows entity expansion during a load
       operation (bsc#1159488, bsc#1186088)" );
	script_tag( name: "affected", value: "'snakeyaml' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "snakeyaml", rpm: "snakeyaml~1.28~3.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "snakeyaml-javadoc", rpm: "snakeyaml-javadoc~1.28~3.5.1", rls: "openSUSELeap15.3" ) )){
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

