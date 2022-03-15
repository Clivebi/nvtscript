if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853933" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2021-25217" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-09 16:47:00 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:04:17 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for dhcp (openSUSE-SU-2021:1841-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1841-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/THX5XKYZAL23HUQMVLFS3L572S4DHQUX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhcp'
  package(s) announced via the openSUSE-SU-2021:1841-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dhcp fixes the following issues:

  - CVE-2021-25217: A buffer overrun in lease file parsing code can be used
       to exploit a common vulnerability shared by dhcpd and dhclient
       (bsc#1186382)" );
	script_tag( name: "affected", value: "'dhcp' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-client-debuginfo", rpm: "dhcp-client-debuginfo~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-debuginfo", rpm: "dhcp-debuginfo~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-debugsource", rpm: "dhcp-debugsource~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-doc", rpm: "dhcp-doc~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-relay-debuginfo", rpm: "dhcp-relay-debuginfo~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-server-debuginfo", rpm: "dhcp-server-debuginfo~4.3.6.P1~6.11.1", rls: "openSUSELeap15.3" ) )){
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

