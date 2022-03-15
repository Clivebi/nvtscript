if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1031" );
	script_cve_id( "CVE-2020-13987", "CVE-2020-13988", "CVE-2020-17437" );
	script_tag( name: "creation_date", value: "2021-01-08 21:52:37 +0000 (Fri, 08 Jan 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-09 15:15:00 +0000 (Tue, 09 Mar 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for open-iscsi (EulerOS-SA-2021-1031)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1031" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1031" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'open-iscsi' package(s) announced via the EulerOS-SA-2021-1031 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in uIP 1.0, as used in Contiki 3.0 and other products. When the Urgent flag is set in a TCP packet, and the stack is configured to ignore the urgent data, the stack attempts to use the value of the Urgent pointer bytes to separate the Urgent data from the normal data, by calculating the offset at which the normal data should be present in the global buffer. However, the length of this offset is not checked, therefore, for large values of the Urgent pointer bytes, the data pointer can point to memory that is way beyond the data buffer in uip_process in uip.c.(CVE-2020-17437)

An issue was discovered in Contiki through 3.0. An Integer Overflow exists in the uIP TCP/IP Stack component when parsing TCP MSS options of IPv4 network packets in uip_process in net/ipv4/uip.c.(CVE-2020-13988)

An issue was discovered in Contiki through 3.0. An Out-of-Bounds Read vulnerability exists in the uIP TCP/IP Stack component when calculating the checksums for IP packets in upper_layer_chksum in net/ipv4/uip.c.(CVE-2020-13987)" );
	script_tag( name: "affected", value: "'open-iscsi' package(s) on Huawei EulerOS V2.0SP9." );
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
if(release == "EULEROS-2.0SP9"){
	if(!isnull( res = isrpmvuln( pkg: "open-iscsi", rpm: "open-iscsi~2.0.876~21.h8.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
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

