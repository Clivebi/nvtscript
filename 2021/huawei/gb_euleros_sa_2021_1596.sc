if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1596" );
	script_cve_id( "CVE-2020-8169", "CVE-2020-8177", "CVE-2020-8231", "CVE-2020-8285", "CVE-2020-8286" );
	script_tag( name: "creation_date", value: "2021-03-12 07:22:24 +0000 (Fri, 12 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 20:00:00 +0000 (Tue, 08 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2021-1596)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1596" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1596" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2021-1596 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Vulnerability Summary for CVE-2020-8169(CVE-2020-8169)

Vulnerability Summary for CVE-2020-8177(CVE-2020-8177)

Expired pointer dereference via multi API with `CURLOPT_CONNECT_ONLY` option set(CVE-2020-8231)

curl 7.21.0 to and including 7.73.0 is vulnerable to uncontrolled recursion due to a stack overflow issue in FTP wildcard match parsing.(CVE-2020-8285)

curl 7.41.0 through 7.73.0 is vulnerable to an improper check for certificate revocation due to insufficient verification of the OCSP response.(CVE-2020-8286)" );
	script_tag( name: "affected", value: "'curl' package(s) on Huawei EulerOS Virtualization release 2.9.1." );
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
if(release == "EULEROSVIRT-2.9.1"){
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.69.1~2.h4.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl", rpm: "libcurl~7.69.1~2.h4.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
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
