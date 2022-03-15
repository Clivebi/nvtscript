if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851954" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2018-9336" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-13 14:27:00 +0000 (Wed, 13 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:22:29 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for openvpn (openSUSE-SU-2018:1912-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:1912-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-07/msg00011.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvpn'
  package(s) announced via the openSUSE-SU-2018:1912-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openvpn fixes the following issues:

  - CVE-2018-9336: Fix potential double-free() in Interactive Service could
  lead to denial of service (bsc#1090839).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-705=1" );
	script_tag( name: "affected", value: "openvpn on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "openvpn", rpm: "openvpn~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-auth-pam-plugin", rpm: "openvpn-auth-pam-plugin~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-auth-pam-plugin-debuginfo", rpm: "openvpn-auth-pam-plugin-debuginfo~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-debuginfo", rpm: "openvpn-debuginfo~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-debugsource", rpm: "openvpn-debugsource~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-devel", rpm: "openvpn-devel~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-down-root-plugin", rpm: "openvpn-down-root-plugin~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-down-root-plugin-debuginfo", rpm: "openvpn-down-root-plugin-debuginfo~2.4.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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
