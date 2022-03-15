if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853640" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-29136" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-20 14:32:00 +0000 (Thu, 20 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:57 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for umoci (openSUSE-SU-2021:0548-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0548-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4ZLXPXB6GF4EU34RGTCCDHJKHSDEN5AN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'umoci'
  package(s) announced via the openSUSE-SU-2021:0548-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for umoci fixes the following issues:

  - Update to umoci v0.4.6.

  - CVE-2021-29136: malicious layer allows overwriting of host files
       (bsc#1184147)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'umoci' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "umoci", rpm: "umoci~0.4.6~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

