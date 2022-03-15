if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1257" );
	script_cve_id( "CVE-2017-0663", "CVE-2017-16931", "CVE-2017-16932" );
	script_tag( name: "creation_date", value: "2020-01-23 11:19:08 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for libxml2 (EulerOS-SA-2018-1257)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1257" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1257" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libxml2' package(s) announced via the EulerOS-SA-2018-1257 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A remote code execution vulnerability in libxml2 could enable an attacker using a specially crafted file to execute arbitrary code within the context of an unprivileged process. This issue is rated as High due to the possibility of remote code execution in an application that uses this library. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2. Android ID: A-37104170.(CVE-2017-0663)

parser.c in libxml2 before 2.9.5 mishandles parameter-entity references because the NEXTL macro calls the xmlParserHandlePEReference function in the case of a '%' character in a DTD name.(CVE-2017-16931)

parser.c in libxml2 before 2.9.5 does not prevent infinite recursion in parameter entities.(CVE-2017-16932)" );
	script_tag( name: "affected", value: "'libxml2' package(s) on Huawei EulerOS Virtualization 2.5.1." );
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
if(release == "EULEROSVIRT-2.5.1"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.9.1~6.3.h3", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.9.1~6.3.h3", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.9.1~6.3.h3", rls: "EULEROSVIRT-2.5.1" ) )){
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

