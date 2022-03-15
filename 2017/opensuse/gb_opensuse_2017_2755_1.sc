if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851627" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-18 16:54:50 +0200 (Wed, 18 Oct 2017)" );
	script_cve_id( "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13087", "CVE-2017-13088" );
	script_tag( name: "cvss_base", value: "2.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for wpa_supplicant (openSUSE-SU-2017:2755-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpa_supplicant'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wpa_supplicant fixes the security issues:

  - Several vulnerabilities in standard conforming implementations of the
  WPA2 protocol have been discovered and published under the code name
  KRACK. This update remedies those issues in a backwards compatible
  manner, i.e. the updated wpa_supplicant can interface properly with both
  vulnerable and patched implementations of WPA2, but an attacker won't be
  able to exploit the KRACK weaknesses in those connections anymore even
  if the other party is still vulnerable. [bsc#1056061, CVE-2017-13078,
  CVE-2017-13079, CVE-2017-13080, CVE-2017-13081, CVE-2017-13087,
  CVE-2017-13088]

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "wpa_supplicant on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2755-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant", rpm: "wpa_supplicant~2.2~9.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debuginfo", rpm: "wpa_supplicant-debuginfo~2.2~9.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debugsource", rpm: "wpa_supplicant-debugsource~2.2~9.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-gui", rpm: "wpa_supplicant-gui~2.2~9.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-gui-debuginfo", rpm: "wpa_supplicant-gui-debuginfo~2.2~9.3.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant", rpm: "wpa_supplicant~2.2~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debuginfo", rpm: "wpa_supplicant-debuginfo~2.2~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debugsource", rpm: "wpa_supplicant-debugsource~2.2~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-gui", rpm: "wpa_supplicant-gui~2.2~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-gui-debuginfo", rpm: "wpa_supplicant-gui-debuginfo~2.2~13.1", rls: "openSUSELeap42.3" ) )){
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

