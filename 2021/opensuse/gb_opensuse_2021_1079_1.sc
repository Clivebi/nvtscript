if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854019" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2021-34558" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-30 14:15:00 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-23 03:01:55 +0000 (Fri, 23 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for go1.15 (openSUSE-SU-2021:1079-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1079-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KY7UHEDTSX6MOHJLHMRNQVBUTCR2XMOB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'go1.15'
  package(s) announced via the openSUSE-SU-2021:1079-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for go1.15 fixes the following issues:

  - go1.15.14 (released 2021-07-12) includes a security fix to the
       crypto/tls package, as well as bug fixes to the linker, and the net
       package. CVE-2021-34558 Refs bsc#1175132 go1.15 release tracking

  * bsc#1188229 go#47143 CVE-2021-34558

  * go#47144 security: fix CVE-2021-34558

  * go#47012 net: LookupMX behaviour broken

  * go#46994 net: TestCVE202133195 fails if /etc/resolv.conf specifies
         ndots larger than 3

  * go#46768 syscall: TestGroupCleanupUserNamespace test failure on Fedora

  * go#46684 x/build/cmd/release: linux-armv6l release tests aren&#x27 t passing

  * go#46656 runtime: deeply nested struct initialized with non-zero values

  - Fix extraneous trailing percent character %endif% in spec file.

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'go1.15' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "go1.15", rpm: "go1.15~1.15.14~lp152.23.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-doc", rpm: "go1.15-doc~1.15.14~lp152.23.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.15-race", rpm: "go1.15-race~1.15.14~lp152.23.1", rls: "openSUSELeap15.2" ) )){
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

