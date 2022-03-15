if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1212" );
	script_cve_id( "CVE-2018-6003" );
	script_tag( name: "creation_date", value: "2020-01-23 11:34:59 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for libtasn1 (EulerOS-SA-2019-1212)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.4" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1212" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1212" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libtasn1' package(s) announced via the EulerOS-SA-2019-1212 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in the _asn1_decode_simple_ber function in decoding.c in GNU Libtasn1 before 4.13. Unlimited recursion in the BER decoder leads to stack exhaustion and DoS.(CVE-2018-6003)" );
	script_tag( name: "affected", value: "'libtasn1' package(s) on Huawei EulerOS Virtualization 2.5.4." );
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
if(release == "EULEROSVIRT-2.5.4"){
	if(!isnull( res = isrpmvuln( pkg: "libtasn1", rpm: "libtasn1~4.10~1.h3", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-devel", rpm: "libtasn1-devel~4.10~1.h3", rls: "EULEROSVIRT-2.5.4" ) )){
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

