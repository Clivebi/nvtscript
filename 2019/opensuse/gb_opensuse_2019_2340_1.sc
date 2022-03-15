if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852743" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-6470" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 21:52:00 +0000 (Wed, 06 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-10-21 02:00:38 +0000 (Mon, 21 Oct 2019)" );
	script_name( "openSUSE: Security Advisory for dhcp (openSUSE-SU-2019:2340-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2340-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00049.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhcp'
  package(s) announced via the openSUSE-SU-2019:2340-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dhcp fixes the following issues:

  Secuirty issue fixed:

  - CVE-2019-6470: Fixed DHCPv6 server crashes (bsc#1134078).

  Bug fixes:

  - Add compile option --enable-secs-byteorder to avoid duplicate lease
  warnings (bsc#1089524).

  - Use IPv6 when called as dhclient6, dhcpd6, and dhcrelay6 (bsc#1136572).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2340=1" );
	script_tag( name: "affected", value: "'dhcp' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-client-debuginfo", rpm: "dhcp-client-debuginfo~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-debuginfo", rpm: "dhcp-debuginfo~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-debugsource", rpm: "dhcp-debugsource~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-doc", rpm: "dhcp-doc~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-relay-debuginfo", rpm: "dhcp-relay-debuginfo~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-server-debuginfo", rpm: "dhcp-server-debuginfo~4.3.5~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
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

