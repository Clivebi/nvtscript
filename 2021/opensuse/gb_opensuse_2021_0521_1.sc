if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853672" );
	script_version( "2021-04-21T07:29:02+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-21 07:29:02 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:36 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for fwupdate (openSUSE-SU-2021:0521-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0521-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y7UA3Z4X5GBSK7YZ2BP6SL2TUTEHCJ6V" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fwupdate'
  package(s) announced via the openSUSE-SU-2021:0521-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for fwupdate fixes the following issues:

  - Add SBAT section to EFI images (bsc#1182057)

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'fwupdate' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "fwupdate", rpm: "fwupdate~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupdate-debuginfo", rpm: "fwupdate-debuginfo~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupdate-debugsource", rpm: "fwupdate-debugsource~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupdate-devel", rpm: "fwupdate-devel~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupdate-efi", rpm: "fwupdate-efi~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupdate-efi-debuginfo", rpm: "fwupdate-efi-debuginfo~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfwup1", rpm: "libfwup1~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfwup1-debuginfo", rpm: "libfwup1-debuginfo~12~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
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

