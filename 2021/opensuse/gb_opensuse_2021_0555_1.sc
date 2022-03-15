if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853745" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-1252", "CVE-2021-1404", "CVE-2021-1405" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 19:56:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:32 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for clamav (openSUSE-SU-2021:0555-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0555-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y6VSAMGIC5SWPJK6HWIGRENALM6YMT46" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the openSUSE-SU-2021:0555-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for clamav fixes the following issues:

  - CVE-2021-1252: Fix for Excel XLM parser infinite loop. (bsc#1184532)

  - CVE-2021-1404: Fix for PDF parser buffer over-read  possible crash.
       (bsc#1184533)

  - CVE-2021-1405: Fix for mail parser NULL-dereference crash. (bsc#1184534)

  - Fix errors when scanning files   4G (bsc#1181256)

  - Update clamav.keyring

  - Update to 0.103.2

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'clamav' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debuginfo", rpm: "clamav-debuginfo~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debugsource", rpm: "clamav-debugsource~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-devel", rpm: "clamav-devel~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libclamav9", rpm: "libclamav9~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libclamav9-debuginfo", rpm: "libclamav9-debuginfo~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreshclam2", rpm: "libfreshclam2~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreshclam2-debuginfo", rpm: "libfreshclam2-debuginfo~0.103.2~lp152.6.6.1", rls: "openSUSELeap15.2" ) )){
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

