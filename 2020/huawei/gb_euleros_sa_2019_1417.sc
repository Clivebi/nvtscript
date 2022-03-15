if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1417" );
	script_cve_id( "CVE-2014-4877", "CVE-2016-4971", "CVE-2016-7098", "CVE-2017-13089", "CVE-2017-13090", "CVE-2018-0494" );
	script_tag( name: "creation_date", value: "2020-01-23 11:43:23 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 14:43:00 +0000 (Wed, 05 May 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for wget (EulerOS-SA-2019-1417)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1417" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1417" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'wget' package(s) announced via the EulerOS-SA-2019-1417 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A stack-based buffer overflow when processing chunked, encoded HTTP responses was found in wget. By tricking an unsuspecting user into connecting to a malicious HTTP server, an attacker could exploit this flaw to potentially execute arbitrary code.(CVE-2017-13089)

A flaw was found in the way Wget handled symbolic links. A malicious FTP server could allow Wget running in the mirror mode (using the '-m' command line option) to write an arbitrary file to a location writable to by the user running Wget, possibly leading to code execution.(CVE-2014-4877)

A cookie injection flaw was found in wget. An attacker can create a malicious website which, when accessed, overrides cookies belonging to arbitrary domains.(CVE-2018-0494)

It was found that wget used a file name provided by the server for the downloaded file when following a HTTP redirect to a FTP server resource. This could cause wget to create a file with a different name than expected, possibly allowing the server to execute arbitrary code on the client.(CVE-2016-4971)

A heap-based buffer overflow, when processing chunked encoded HTTP responses, was found in wget. By tricking an unsuspecting user into connecting to a malicious HTTP server, an attacker could exploit this flaw to potentially execute arbitrary code.(CVE-2017-13090)

Race condition in wget 1.17 and earlier, when used in recursive or mirroring mode to download a single file, might allow remote servers to bypass intended access list restrictions by keeping an HTTP connection open.(CVE-2016-7098)" );
	script_tag( name: "affected", value: "'wget' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "wget", rpm: "wget~1.14~15.1.h5", rls: "EULEROSVIRT-3.0.1.0" ) )){
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
