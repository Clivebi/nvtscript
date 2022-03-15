if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854087" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-3652" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-21 03:01:49 +0000 (Sat, 21 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for 389-ds (openSUSE-SU-2021:2801-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2801-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/E6YUB5M37IM7IMXZ65R3QTW6TPO6B3OS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the '389-ds'
  package(s) announced via the openSUSE-SU-2021:2801-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for 389-ds fixes the following issues:

  - Update to 1.4.4.16

  - CVE-2021-3652: Fixed crypt handling of locked accounts. (bsc#1188455)" );
	script_tag( name: "affected", value: "'389-ds' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "389-ds-1.4.4.16", rpm: "389-ds-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-debuginfo-1.4.4.16", rpm: "389-ds-debuginfo-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-debugsource-1.4.4.16", rpm: "389-ds-debugsource-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-devel-1.4.4.16", rpm: "389-ds-devel-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-snmp-1.4.4.16", rpm: "389-ds-snmp-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-snmp-debuginfo-1.4.4.16", rpm: "389-ds-snmp-debuginfo-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib389-1.4.4.16", rpm: "lib389-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsvrcore0-1.4.4.16", rpm: "libsvrcore0-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsvrcore0-debuginfo-1.4.4.16", rpm: "libsvrcore0-debuginfo-1.4.4.16~git16.c1926dfc6~3.4.1", rls: "openSUSELeap15.3" ) )){
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

