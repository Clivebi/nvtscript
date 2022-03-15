if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1193" );
	script_cve_id( "CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815", "CVE-2018-3639" );
	script_tag( name: "creation_date", value: "2020-01-23 11:16:26 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for java-1.7.0-openjdk (EulerOS-SA-2018-1193)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1193" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1193" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'java-1.7.0-openjdk' package(s) announced via the EulerOS-SA-2018-1193 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenJDK: incorrect handling of Reference clones can lead to sandbox bypass.(CVE-2018-2814)

OpenJDK: unrestricted deserialization of data from JCEKS key stores.(CVE-2018-2794)

OpenJDK: insufficient consistency checks in deserialization of multiple classes.(CVE-2018-2795)

OpenJDK: unbounded memory allocation during deserialization in PriorityBlockingQueue.(CVE-2018-2796)

OpenJDK: unbounded memory allocation during deserialization in TabularDataSupport. (CVE-2018-2797)

OpenJDK: unbounded memory allocation during deserialization in Container.(CVE-2018-2798)

OpenJDK: unbounded memory allocation during deserialization in NamedNodeMapImpl.(CVE-2018-2799)

OpenJDK: RMI HTTP transport enabled by default.(CVE-2018-2800)

OpenJDK: unbounded memory allocation during deserialization in StubIORImpl.(CVE-2018-2815)

OpenJDK: incorrect merging of sections in the JAR manifest.(CVE-2018-2790)

An industry-wide issue was found in the way many modern microprocessor designs have implemented speculative execution of Load & Store instructions (a commonly used performance optimization). It relies on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that memory read from address to which a recent memory write has occurred may see an older value and subsequently cause an update into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to read privileged memory by conducting targeted cache side-channel attacks.(CVE-2018-3639)" );
	script_tag( name: "affected", value: "'java-1.7.0-openjdk' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.181~2.6.14.8", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.181~2.6.14.8", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk-headless", rpm: "java-1.7.0-openjdk-headless~1.7.0.181~2.6.14.8", rls: "EULEROS-2.0SP3" ) )){
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

