if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1650" );
	script_cve_id( "CVE-2018-20102", "CVE-2018-20103", "CVE-2018-20615" );
	script_tag( name: "creation_date", value: "2020-01-23 12:19:00 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 14:29:00 +0000 (Tue, 11 Jun 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for haproxy (EulerOS-SA-2019-1650)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1650" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1650" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'haproxy' package(s) announced via the EulerOS-SA-2019-1650 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An out-of-bounds read issue was discovered in the HTTP/2 protocol decoder in HAProxy 1.8.x and 1.9.x through 1.9.0 which can result in a crash. The processing of the PRIORITY flag in a HEADERS frame requires 5 extra bytes, and while these bytes are skipped, the total frame length was not re-checked to make sure they were present in the frame.(CVE-2018-20615)

An issue was discovered in dns.c in HAProxy through 1.8.14. In the case of a compressed pointer, a crafted packet can trigger infinite recursion by making the pointer point to itself, or create a long chain of valid pointers resulting in stack exhaustion.(CVE-2018-20103)

An out-of-bounds read in dns_validate_dns_response in dns.c was discovered in HAProxy through 1.8.14. Due to a missing check when validating DNS responses, remote attackers might be able read the 16 bytes corresponding to an AAAA record from the non-initialized part of the buffer, possibly accessing anything that was left on the stack, or even past the end of the 8193-byte buffer, depending on the value of accepted_payload_size.(CVE-2018-20102)" );
	script_tag( name: "affected", value: "'haproxy' package(s) on Huawei EulerOS V2.0SP8." );
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
if(release == "EULEROS-2.0SP8"){
	if(!isnull( res = isrpmvuln( pkg: "haproxy", rpm: "haproxy~1.8.14~1.h1.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

