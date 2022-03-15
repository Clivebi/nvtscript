if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854069" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-38185" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-16 15:35:00 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-17 03:01:39 +0000 (Tue, 17 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for cpio (openSUSE-SU-2021:2689-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2689-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XORUFH2I27QQWZXGSRUKWLXW5NX5KLXA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cpio'
  package(s) announced via the openSUSE-SU-2021:2689-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cpio fixes the following issues:

     It was possible to trigger Remote code execution due to a integer overflow
     (CVE-2021-38185, bsc#1189206)

     UPDATE: This update was buggy and could lead to hangs, so it has been
     retracted. There will be a follow up update." );
	script_tag( name: "affected", value: "'cpio' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "cpio", rpm: "cpio~2.12~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-debuginfo", rpm: "cpio-debuginfo~2.12~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-debugsource", rpm: "cpio-debugsource~2.12~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-mt", rpm: "cpio-mt~2.12~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-mt-debuginfo", rpm: "cpio-mt-debuginfo~2.12~3.6.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-lang", rpm: "cpio-lang~2.12~3.6.1", rls: "openSUSELeap15.3" ) )){
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

