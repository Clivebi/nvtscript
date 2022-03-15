if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0179.1" );
	script_cve_id( "CVE-2018-1000845" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-09 15:01:50 +0000 (Wed, 09 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0179-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3|SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0179-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190179-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'avahi' package(s) announced via the SUSE-SU-2019:0179-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for avahi fixes the following issues:

Security issue fixed:
CVE-2018-1000845: Fixed DNS amplification and reflection to spoofed
 addresses (DOS) (bsc#1120281)" );
	script_tag( name: "affected", value: "'avahi' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP4." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "avahi", rpm: "avahi~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debuginfo", rpm: "avahi-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debuginfo-32bit", rpm: "avahi-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debugsource", rpm: "avahi-debugsource~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-glib2-debugsource", rpm: "avahi-glib2-debugsource~0.6.32~32.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-lang", rpm: "avahi-lang~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils", rpm: "avahi-utils~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils-debuginfo", rpm: "avahi-utils-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3", rpm: "libavahi-client3~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-32bit", rpm: "libavahi-client3-32bit~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-debuginfo", rpm: "libavahi-client3-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-debuginfo-32bit", rpm: "libavahi-client3-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3", rpm: "libavahi-common3~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-32bit", rpm: "libavahi-common3-32bit~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-debuginfo", rpm: "libavahi-common3-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-debuginfo-32bit", rpm: "libavahi-common3-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-core7", rpm: "libavahi-core7~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-core7-debuginfo", rpm: "libavahi-core7-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1", rpm: "libavahi-glib1~0.6.32~32.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1-32bit", rpm: "libavahi-glib1-32bit~0.6.32~32.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1-debuginfo", rpm: "libavahi-glib1-debuginfo~0.6.32~32.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1-debuginfo-32bit", rpm: "libavahi-glib1-debuginfo-32bit~0.6.32~32.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd", rpm: "libdns_sd~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd-32bit", rpm: "libdns_sd-32bit~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd-debuginfo", rpm: "libdns_sd-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd-debuginfo-32bit", rpm: "libdns_sd-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "avahi", rpm: "avahi~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debuginfo", rpm: "avahi-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debuginfo-32bit", rpm: "avahi-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debugsource", rpm: "avahi-debugsource~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-glib2-debugsource", rpm: "avahi-glib2-debugsource~0.6.32~32.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-lang", rpm: "avahi-lang~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils", rpm: "avahi-utils~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils-debuginfo", rpm: "avahi-utils-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3", rpm: "libavahi-client3~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-32bit", rpm: "libavahi-client3-32bit~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-debuginfo", rpm: "libavahi-client3-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-debuginfo-32bit", rpm: "libavahi-client3-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3", rpm: "libavahi-common3~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-32bit", rpm: "libavahi-common3-32bit~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-debuginfo", rpm: "libavahi-common3-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-debuginfo-32bit", rpm: "libavahi-common3-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-core7", rpm: "libavahi-core7~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-core7-debuginfo", rpm: "libavahi-core7-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1", rpm: "libavahi-glib1~0.6.32~32.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1-32bit", rpm: "libavahi-glib1-32bit~0.6.32~32.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1-debuginfo", rpm: "libavahi-glib1-debuginfo~0.6.32~32.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1-debuginfo-32bit", rpm: "libavahi-glib1-debuginfo-32bit~0.6.32~32.3.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd", rpm: "libdns_sd~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd-32bit", rpm: "libdns_sd-32bit~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd-debuginfo", rpm: "libdns_sd-debuginfo~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd-debuginfo-32bit", rpm: "libdns_sd-debuginfo-32bit~0.6.32~32.3.1", rls: "SLES12.0SP4" ) )){
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

