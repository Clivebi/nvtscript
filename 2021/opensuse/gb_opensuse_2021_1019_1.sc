if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853943" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-27208" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 15:41:00 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:04:38 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for solo (openSUSE-SU-2021:1019-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1019-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KVSCA7DKULXER7BGQ3YJN34AY5RPCIU5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'solo'
  package(s) announced via the openSUSE-SU-2021:1019-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for solo fixes the following issues:

     Update to Solo 4.1.2

  * Fix boo#1186848 CVE-202-27208, security issue in firmware source that is
       part of the source package." );
	script_tag( name: "affected", value: "'solo' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "solo-udev", rpm: "solo-udev~4.1.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

