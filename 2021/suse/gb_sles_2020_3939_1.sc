if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3939.1" );
	script_cve_id( "CVE-2019-19906" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3939-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3939-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203939-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cyrus-sasl' package(s) announced via the SUSE-SU-2020:3939-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cyrus-sasl fixes the following issues:

CVE-2019-19906: Fixed an out-of-bounds write leading to unauthenticated
 remote denial-of-service in OpenLDAP via a malformed LDAP packet
 (bsc#1159635)." );
	script_tag( name: "affected", value: "'cyrus-sasl' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl", rpm: "cyrus-sasl~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-32bit", rpm: "cyrus-sasl-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5", rpm: "cyrus-sasl-crammd5~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-32bit", rpm: "cyrus-sasl-crammd5-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo", rpm: "cyrus-sasl-crammd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo-32bit", rpm: "cyrus-sasl-crammd5-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo", rpm: "cyrus-sasl-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo-32bit", rpm: "cyrus-sasl-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debugsource", rpm: "cyrus-sasl-debugsource~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5", rpm: "cyrus-sasl-digestmd5~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5-debuginfo", rpm: "cyrus-sasl-digestmd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi", rpm: "cyrus-sasl-gssapi~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-32bit", rpm: "cyrus-sasl-gssapi-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo", rpm: "cyrus-sasl-gssapi-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo-32bit", rpm: "cyrus-sasl-gssapi-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp", rpm: "cyrus-sasl-otp~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-32bit", rpm: "cyrus-sasl-otp-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo", rpm: "cyrus-sasl-otp-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo-32bit", rpm: "cyrus-sasl-otp-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain", rpm: "cyrus-sasl-plain~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-32bit", rpm: "cyrus-sasl-plain-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo", rpm: "cyrus-sasl-plain-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo-32bit", rpm: "cyrus-sasl-plain-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3", rpm: "libsasl2-3~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-32bit", rpm: "libsasl2-3-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo", rpm: "libsasl2-3-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo-32bit", rpm: "libsasl2-3-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl", rpm: "cyrus-sasl~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-32bit", rpm: "cyrus-sasl-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5", rpm: "cyrus-sasl-crammd5~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-32bit", rpm: "cyrus-sasl-crammd5-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo", rpm: "cyrus-sasl-crammd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo-32bit", rpm: "cyrus-sasl-crammd5-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo", rpm: "cyrus-sasl-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo-32bit", rpm: "cyrus-sasl-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debugsource", rpm: "cyrus-sasl-debugsource~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5", rpm: "cyrus-sasl-digestmd5~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5-debuginfo", rpm: "cyrus-sasl-digestmd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi", rpm: "cyrus-sasl-gssapi~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-32bit", rpm: "cyrus-sasl-gssapi-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo", rpm: "cyrus-sasl-gssapi-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo-32bit", rpm: "cyrus-sasl-gssapi-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp", rpm: "cyrus-sasl-otp~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-32bit", rpm: "cyrus-sasl-otp-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo", rpm: "cyrus-sasl-otp-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo-32bit", rpm: "cyrus-sasl-otp-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain", rpm: "cyrus-sasl-plain~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-32bit", rpm: "cyrus-sasl-plain-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo", rpm: "cyrus-sasl-plain-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo-32bit", rpm: "cyrus-sasl-plain-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3", rpm: "libsasl2-3~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-32bit", rpm: "libsasl2-3-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo", rpm: "libsasl2-3-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo-32bit", rpm: "libsasl2-3-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl", rpm: "cyrus-sasl~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-32bit", rpm: "cyrus-sasl-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5", rpm: "cyrus-sasl-crammd5~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-32bit", rpm: "cyrus-sasl-crammd5-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo", rpm: "cyrus-sasl-crammd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo-32bit", rpm: "cyrus-sasl-crammd5-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo", rpm: "cyrus-sasl-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo-32bit", rpm: "cyrus-sasl-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debugsource", rpm: "cyrus-sasl-debugsource~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5", rpm: "cyrus-sasl-digestmd5~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5-debuginfo", rpm: "cyrus-sasl-digestmd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi", rpm: "cyrus-sasl-gssapi~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-32bit", rpm: "cyrus-sasl-gssapi-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo", rpm: "cyrus-sasl-gssapi-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo-32bit", rpm: "cyrus-sasl-gssapi-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp", rpm: "cyrus-sasl-otp~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-32bit", rpm: "cyrus-sasl-otp-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo", rpm: "cyrus-sasl-otp-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo-32bit", rpm: "cyrus-sasl-otp-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain", rpm: "cyrus-sasl-plain~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-32bit", rpm: "cyrus-sasl-plain-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo", rpm: "cyrus-sasl-plain-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo-32bit", rpm: "cyrus-sasl-plain-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3", rpm: "libsasl2-3~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-32bit", rpm: "libsasl2-3-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo", rpm: "libsasl2-3-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo-32bit", rpm: "libsasl2-3-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl", rpm: "cyrus-sasl~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-32bit", rpm: "cyrus-sasl-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5", rpm: "cyrus-sasl-crammd5~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-32bit", rpm: "cyrus-sasl-crammd5-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo", rpm: "cyrus-sasl-crammd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-crammd5-debuginfo-32bit", rpm: "cyrus-sasl-crammd5-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo", rpm: "cyrus-sasl-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo-32bit", rpm: "cyrus-sasl-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debugsource", rpm: "cyrus-sasl-debugsource~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5", rpm: "cyrus-sasl-digestmd5~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-digestmd5-debuginfo", rpm: "cyrus-sasl-digestmd5-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi", rpm: "cyrus-sasl-gssapi~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-32bit", rpm: "cyrus-sasl-gssapi-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo", rpm: "cyrus-sasl-gssapi-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi-debuginfo-32bit", rpm: "cyrus-sasl-gssapi-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp", rpm: "cyrus-sasl-otp~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-32bit", rpm: "cyrus-sasl-otp-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo", rpm: "cyrus-sasl-otp-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-otp-debuginfo-32bit", rpm: "cyrus-sasl-otp-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain", rpm: "cyrus-sasl-plain~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-32bit", rpm: "cyrus-sasl-plain-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo", rpm: "cyrus-sasl-plain-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain-debuginfo-32bit", rpm: "cyrus-sasl-plain-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3", rpm: "libsasl2-3~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-32bit", rpm: "libsasl2-3-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo", rpm: "libsasl2-3-debuginfo~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsasl2-3-debuginfo-32bit", rpm: "libsasl2-3-debuginfo-32bit~2.1.26~8.13.1", rls: "SLES12.0SP5" ) )){
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

