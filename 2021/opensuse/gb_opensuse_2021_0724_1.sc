if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853811" );
	script_version( "2021-05-25T12:16:58+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-25 12:16:58 +0000 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-15 03:01:33 +0000 (Sat, 15 May 2021)" );
	script_name( "openSUSE: Security Advisory for drbd-utils (openSUSE-SU-2021:0724-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0724-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BWRKSZ3IK3R2W4X6HVYDM5ZUN7FBGGSZ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drbd-utils'
  package(s) announced via the openSUSE-SU-2021:0724-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for drbd-utils fixes the following issues:

  - make all binaries in position independent (bsc#1185132).

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'drbd-utils' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "drbd-utils", rpm: "drbd-utils~9.13.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "drbd-utils-debuginfo", rpm: "drbd-utils-debuginfo~9.13.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "drbd-utils-debugsource", rpm: "drbd-utils-debugsource~9.13.0~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
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

