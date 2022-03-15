if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853817" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2018-7544", "CVE-2020-11810", "CVE-2020-15078" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-10 15:15:00 +0000 (Tue, 10 Apr 2018)" );
	script_tag( name: "creation_date", value: "2021-05-17 03:01:13 +0000 (Mon, 17 May 2021)" );
	script_name( "openSUSE: Security Advisory for openvpn (openSUSE-SU-2021:0734-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0734-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/C5VK3H4AGK4ZRCLIB2D3IB7SS5RI4AZK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvpn'
  package(s) announced via the openSUSE-SU-2021:0734-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openvpn fixes the following issues:

  - CVE-2020-15078: Fixed authentication bypass with deferred authentication
       (bsc#1185279).

  - CVE-2020-11810: Fixed race condition between allocating peer-id and
       initializing data channel key (bsc#1169925).

  - CVE-2018-7544: Fixed cross-protocol scripting issue that was discovered
       in the management interface (bsc#1085803).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'openvpn' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "openvpn", rpm: "openvpn~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-auth-pam-plugin", rpm: "openvpn-auth-pam-plugin~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-auth-pam-plugin-debuginfo", rpm: "openvpn-auth-pam-plugin-debuginfo~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-debuginfo", rpm: "openvpn-debuginfo~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-debugsource", rpm: "openvpn-debugsource~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-devel", rpm: "openvpn-devel~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-down-root-plugin", rpm: "openvpn-down-root-plugin~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-down-root-plugin-debuginfo", rpm: "openvpn-down-root-plugin-debuginfo~2.4.3~lp152.6.3.1", rls: "openSUSELeap15.2" ) )){
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

