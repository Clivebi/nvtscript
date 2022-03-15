if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853878" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2021-3580" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-13 17:51:00 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-25 03:01:30 +0000 (Fri, 25 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for libnettle (openSUSE-SU-2021:0906-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0906-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/D4XGPKTRWLOEATNJNZGQZCO6BZTKIKJ6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libnettle'
  package(s) announced via the openSUSE-SU-2021:0906-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libnettle fixes the following issues:

  - CVE-2021-3580: Fixed a remote denial of service in the RSA decryption
       via manipulated ciphertext (bsc#1187060).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'libnettle' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4", rpm: "libhogweed4~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-debuginfo", rpm: "libhogweed4-debuginfo~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-debugsource", rpm: "libnettle-debugsource~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-devel", rpm: "libnettle-devel~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6", rpm: "libnettle6~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-debuginfo", rpm: "libnettle6-debuginfo~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nettle", rpm: "nettle~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nettle-debuginfo", rpm: "nettle-debuginfo~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit", rpm: "libhogweed4-32bit~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhogweed4-32bit-debuginfo", rpm: "libhogweed4-32bit-debuginfo~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle-devel-32bit", rpm: "libnettle-devel-32bit~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit", rpm: "libnettle6-32bit~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnettle6-32bit-debuginfo", rpm: "libnettle6-32bit-debuginfo~3.4.1~lp152.4.6.1", rls: "openSUSELeap15.2" ) )){
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

