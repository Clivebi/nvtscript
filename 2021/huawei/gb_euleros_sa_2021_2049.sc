if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2049" );
	script_cve_id( "CVE-2021-22876", "CVE-2021-22890" );
	script_tag( name: "creation_date", value: "2021-07-01 07:40:50 +0000 (Thu, 01 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2021-2049)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9\\-X86_64" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2049" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2049" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2021-2049 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "curl 7.63.0 to and including 7.75.0 includes vulnerability that allows a malicious HTTPS proxy to MITM a connection due to bad handling of TLS 1.3 session tickets. When using a HTTPS proxy and TLS 1.3, libcurl can confuse session tickets arriving from the HTTPS proxy but work as if they arrived from the remote server and then wrongly(CVE-2021-22890)

curl 7.1.1 to and including 7.75.0 is vulnerable to an 'Exposure of Private Personal Information to an Unauthorized Actor' by leaking credentials in the HTTP Referer: header. libcurl does not strip off user credentials from the URL when automatically populating the Referer: HTTP request header field in outgoing HTTP requests, and therefore risks leaking sensitive data to the server that is the target of the second HTTP request.(CVE-2021-22876)" );
	script_tag( name: "affected", value: "'curl' package(s) on Huawei EulerOS V2.0SP9(x86_64)." );
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
if(release == "EULEROS-2.0SP9-x86_64"){
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.69.1~2.h7.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl", rpm: "libcurl~7.69.1~2.h7.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
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

