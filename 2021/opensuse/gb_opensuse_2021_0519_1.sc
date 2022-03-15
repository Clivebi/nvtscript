if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853706" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2019-16275", "CVE-2020-12695", "CVE-2021-30004" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 00:15:00 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:00:56 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for hostapd (openSUSE-SU-2021:0519-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0519-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EXT3Y5NEGCCPGZ7FTYURPUBTHNNJA6MF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hostapd'
  package(s) announced via the openSUSE-SU-2021:0519-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for hostapd fixes the following issues:

  - CVE-2021-30004: forging attacks may occur because AlgorithmIdentifier
       parameters are mishandled in tls/pkcs1.c and tls/x509v3.c (boo#1184348)

  - CVE-2020-12695: UPnP SUBSCRIBE misbehavior in hostapd WPS AP
       (boo#1172700)

  - CVE-2019-16275: AP mode PMF disconnection protection bypass (boo#1150934)

  - added AppArmor profile (source apparmor-usr.sbin.hostapd)" );
	script_tag( name: "affected", value: "'hostapd' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "hostapd", rpm: "hostapd~2.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hostapd-debuginfo", rpm: "hostapd-debuginfo~2.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hostapd-debugsource", rpm: "hostapd-debugsource~2.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

