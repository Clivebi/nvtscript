if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853603" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-35518" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-01 14:56:00 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:56:24 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for 389-ds (openSUSE-SU-2021:0418-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0418-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IJZAIJRIBNKFP5CET6TYMJ3FGMU6WYAM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the '389-ds'
  package(s) announced via the openSUSE-SU-2021:0418-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for 389-ds fixes the following issues:

  - 389-ds was updated to version 1.4.3.19

  - CVE-2020-35518: Fixed an information disclosure during the binding of
          a DN (bsc#1181159).

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'389-ds' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "389-ds-1.4.3.19", rpm: "389-ds-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-debuginfo-1.4.3.19", rpm: "389-ds-debuginfo-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-debugsource-1.4.3.19", rpm: "389-ds-debugsource-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-devel-1.4.3.19", rpm: "389-ds-devel-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-snmp-1.4.3.19", rpm: "389-ds-snmp-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-snmp-debuginfo-1.4.3.19", rpm: "389-ds-snmp-debuginfo-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib389-1.4.3.19", rpm: "lib389-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibsvrcore0-1.4.3.19", rpm: "libsvrcore0-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsvrcore0-debuginfo-1.4.3.19", rpm: "libsvrcore0-debuginfo-1.4.3.19~git0.bef0b5bed~lp152.2.12.1", rls: "openSUSELeap15.2" ) )){
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

