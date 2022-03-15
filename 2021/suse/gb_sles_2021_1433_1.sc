if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1433.1" );
	script_cve_id( "CVE-2021-23961", "CVE-2021-23994", "CVE-2021-23995", "CVE-2021-23998", "CVE-2021-23999", "CVE-2021-24002", "CVE-2021-29945", "CVE-2021-29946" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-02 16:55:00 +0000 (Fri, 02 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1433-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1433-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211433-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2021:1433-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaFirefox fixes the following issues:

MozillaFirefox was updated to 78.10.0 ESR (bsc#1184960)
 * CVE-2021-23994: Out of bound write due to lazy initialization
 * CVE-2021-23995: Use-after-free in Responsive Design Mode
 * CVE-2021-23998: Secure Lock icon could have been spoofed
 * CVE-2021-23961: More internal network hosts could have been probed by
 a malicious webpage
 * CVE-2021-23999: Blob URLs may have been granted additional privileges
 * CVE-2021-24002: Arbitrary FTP command execution on FTP servers using
 an encoded URL
 * CVE-2021-29945: Incorrect size computation in WebAssembly JIT could
 lead to null-reads
 * CVE-2021-29946: Port blocking could be bypassed" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~78.10.0~3.139.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~78.10.0~3.139.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~78.10.0~3.139.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~78.10.0~3.139.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~78.10.0~3.139.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~78.10.0~3.139.1", rls: "SLES15.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~78.10.0~3.139.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~78.10.0~3.139.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~78.10.0~3.139.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~78.10.0~3.139.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~78.10.0~3.139.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~78.10.0~3.139.1", rls: "SLES15.0SP1" ) )){
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

