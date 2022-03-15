if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1457" );
	script_cve_id( "CVE-2018-1320", "CVE-2019-0205", "CVE-2019-0210" );
	script_tag( name: "creation_date", value: "2021-03-05 07:07:05 +0000 (Fri, 05 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-15 16:15:00 +0000 (Thu, 15 Apr 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for thrift (EulerOS-SA-2021-1457)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.6\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1457" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1457" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'thrift' package(s) announced via the EulerOS-SA-2021-1457 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Apache Thrift 0.9.3 to 0.12.0, a server implemented in Go using TJSONProtocol or TSimpleJSONProtocol may panic when feed with invalid input data.(CVE-2019-0210)

In Apache Thrift all versions up to and including 0.12.0, a server or client may run into an endless loop when feed with specific input data. Because the issue had already been partially fixed in version 0.11.0, depending on the installed version it affects only certain language bindings.(CVE-2019-0205)

Apache Thrift Java client library versions 0.5.0 through 0.11.0 can bypass SASL negotiation isComplete validation in the org.apache.thrift.transport.TSaslTransport class. An assert used to determine if the SASL handshake had successfully completed could be disabled in production settings making the validation incomplete.(CVE-2018-1320)" );
	script_tag( name: "affected", value: "'thrift' package(s) on Huawei EulerOS Virtualization 3.0.6.6." );
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
if(release == "EULEROSVIRT-3.0.6.6"){
	if(!isnull( res = isrpmvuln( pkg: "thrift-lib-cpp", rpm: "thrift-lib-cpp~0.9.3.1~1", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "thrift-lib-python", rpm: "thrift-lib-python~0.9.3.1~1", rls: "EULEROSVIRT-3.0.6.6" ) )){
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

