if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852531" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2018-1000135" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 12:29:00 +0000 (Mon, 03 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-04 02:00:47 +0000 (Tue, 04 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for NetworkManager (openSUSE-SU-2019:1494-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1494-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00005.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'NetworkManager'
  package(s) announced via the openSUSE-SU-2019:1494-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for NetworkManager fixes the following issues:

  The following security issue was fixed:

  - CVE-2018-1000135: A potential leak of private DNS queries to other DNS
  servers could happen while on VPN (bsc#1086263, bgo#746422).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1494=1" );
	script_tag( name: "affected", value: "'NetworkManager' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager", rpm: "NetworkManager~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-debuginfo", rpm: "NetworkManager-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-debugsource", rpm: "NetworkManager-debugsource~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-devel", rpm: "NetworkManager-devel~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib-vpn1", rpm: "libnm-glib-vpn1~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib-vpn1-debuginfo", rpm: "libnm-glib-vpn1-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib4", rpm: "libnm-glib4~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib4-debuginfo", rpm: "libnm-glib4-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-util2", rpm: "libnm-util2~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-util2-debuginfo", rpm: "libnm-util2-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm0", rpm: "libnm0~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm0-debuginfo", rpm: "libnm0-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-NM-1_0", rpm: "typelib-1_0-NM-1_0~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-NMClient-1_0", rpm: "typelib-1_0-NMClient-1_0~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-NetworkManager-1_0", rpm: "typelib-1_0-NetworkManager-1_0~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-devel-32bit", rpm: "NetworkManager-devel-32bit~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib-vpn1-32bit", rpm: "libnm-glib-vpn1-32bit~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib-vpn1-32bit-debuginfo", rpm: "libnm-glib-vpn1-32bit-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib4-32bit", rpm: "libnm-glib4-32bit~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-glib4-32bit-debuginfo", rpm: "libnm-glib4-32bit-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-util2-32bit", rpm: "libnm-util2-32bit~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnm-util2-32bit-debuginfo", rpm: "libnm-util2-32bit-debuginfo~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-branding-upstream", rpm: "NetworkManager-branding-upstream~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "NetworkManager-lang", rpm: "NetworkManager-lang~1.10.6~lp150.4.6.1", rls: "openSUSELeap15.0" ) )){
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

