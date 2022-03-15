if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853719" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-10759" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-22 16:51:00 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:01:33 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for fwupd (openSUSE-SU-2021:0522-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0522-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PR4WC2OGLKRFBB7HJ3YCZ6PTJUJK67B4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fwupd'
  package(s) announced via the openSUSE-SU-2021:0522-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for fwupd fixes the following issues:

  - Update to version 1.2.14: (bsc#1182057)

  - Add SBAT section to EFI images (bsc#1182057)

  - CVE-2020-10759: Validate that gpgme_op_verify_result() returned at least
       one signature (bsc#1172643)

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'fwupd' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "dfu-tool", rpm: "dfu-tool~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dfu-tool-debuginfo", rpm: "dfu-tool-debuginfo~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupd", rpm: "fwupd~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupd-debuginfo", rpm: "fwupd-debuginfo~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupd-debugsource", rpm: "fwupd-debugsource~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupd-devel", rpm: "fwupd-devel~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfwupd2", rpm: "libfwupd2~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfwupd2-debuginfo", rpm: "libfwupd2-debuginfo~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Fwupd-2_0", rpm: "typelib-1_0-Fwupd-2_0~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fwupd-lang", rpm: "fwupd-lang~1.2.14~lp152.3.9.1", rls: "openSUSELeap15.2" ) )){
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

