if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1164.1" );
	script_cve_id( "CVE-2020-13987", "CVE-2020-13988", "CVE-2020-17437", "CVE-2020-17438" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-15 16:34:00 +0000 (Tue, 15 Dec 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1164-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3|SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1164-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211164-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'open-iscsi' package(s) announced via the SUSE-SU-2021:1164-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for open-iscsi fixes the following issues:

CVE-2020-17437: uIP Out-of-Bounds Write (bsc#1179908)

CVE-2020-17438: uIP Out-of-Bounds Write (bsc#1179908)

CVE-2020-13987: uIP Out-of-Bounds Read (bsc#1179908)

CVE-2020-13988: uIP Integer Overflow (bsc#1179908)

Enabled no-wait ('-W') iscsiadm option for iscsi login service
 (bsc#1173886, bsc#1183421)

Added the ability to perform async logins (bsc#1173886)" );
	script_tag( name: "affected", value: "'open-iscsi' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debuginfo", rpm: "open-iscsi-debuginfo~2.0.876~13.42.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debugsource", rpm: "open-iscsi-debugsource~2.0.876~13.42.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debuginfo", rpm: "open-iscsi-debuginfo~2.0.876~13.42.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debugsource", rpm: "open-iscsi-debugsource~2.0.876~13.42.1", rls: "SLES15.0SP3" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "iscsiuio", rpm: "iscsiuio~0.7.8.2~13.42.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsiuio-debuginfo", rpm: "iscsiuio-debuginfo~0.7.8.2~13.42.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopeniscsiusr0_2_0", rpm: "libopeniscsiusr0_2_0~2.0.876~13.42.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopeniscsiusr0_2_0-debuginfo", rpm: "libopeniscsiusr0_2_0-debuginfo~2.0.876~13.42.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi", rpm: "open-iscsi~2.0.876~13.42.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debuginfo", rpm: "open-iscsi-debuginfo~2.0.876~13.42.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debugsource", rpm: "open-iscsi-debugsource~2.0.876~13.42.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-devel", rpm: "open-iscsi-devel~2.0.876~13.42.1", rls: "SLES15.0" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "iscsiuio", rpm: "iscsiuio~0.7.8.2~13.42.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsiuio-debuginfo", rpm: "iscsiuio-debuginfo~0.7.8.2~13.42.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopeniscsiusr0_2_0", rpm: "libopeniscsiusr0_2_0~2.0.876~13.42.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopeniscsiusr0_2_0-debuginfo", rpm: "libopeniscsiusr0_2_0-debuginfo~2.0.876~13.42.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi", rpm: "open-iscsi~2.0.876~13.42.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debuginfo", rpm: "open-iscsi-debuginfo~2.0.876~13.42.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-debugsource", rpm: "open-iscsi-debugsource~2.0.876~13.42.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi-devel", rpm: "open-iscsi-devel~2.0.876~13.42.1", rls: "SLES15.0SP1" ) )){
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

