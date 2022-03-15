if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0132.1" );
	script_cve_id( "CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6110", "CVE-2019-6111" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0132-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0132-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190132-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2019:0132-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssh fixes the following issues:

Security issue fixed:
CVE-2018-20685: Fixed an issue where scp client allows remote SSH
 servers to bypass intended access restrictions (bsc#1121571)

CVE-2019-6109: Fixed an issue where the scp client would allow malicious
 remote SSH servers to manipulate terminal output via the object name,
 e.g. by inserting ANSI escape sequences (bsc#1121816)

CVE-2019-6110: Fixed an issue where the scp client would allow malicious
 remote SSH servers to manipulate stderr output, e.g. by inserting ANSI
 escape sequences (bsc#1121818)

CVE-2019-6111: Fixed an issue where the scp client would allow malicious
 remote SSH servers to execute directory traversal attacks and overwrite
 files (bsc#1121821)" );
	script_tag( name: "affected", value: "'openssh' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome", rpm: "openssh-askpass-gnome~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome-debuginfo", rpm: "openssh-askpass-gnome-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debugsource", rpm: "openssh-debugsource~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-fips", rpm: "openssh-fips~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers", rpm: "openssh-helpers~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers-debuginfo", rpm: "openssh-helpers-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome", rpm: "openssh-askpass-gnome~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome-debuginfo", rpm: "openssh-askpass-gnome-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debugsource", rpm: "openssh-debugsource~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-fips", rpm: "openssh-fips~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers", rpm: "openssh-helpers~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers-debuginfo", rpm: "openssh-helpers-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome", rpm: "openssh-askpass-gnome~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome-debuginfo", rpm: "openssh-askpass-gnome-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debugsource", rpm: "openssh-debugsource~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-fips", rpm: "openssh-fips~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers", rpm: "openssh-helpers~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers-debuginfo", rpm: "openssh-helpers-debuginfo~7.2p2~74.35.1", rls: "SLES12.0SP4" ) )){
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

