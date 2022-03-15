if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2477" );
	script_cve_id( "CVE-2021-20298", "CVE-2021-20299", "CVE-2021-20303", "CVE-2021-20304" );
	script_tag( name: "creation_date", value: "2021-09-24 02:24:28 +0000 (Fri, 24 Sep 2021)" );
	script_version( "2021-09-24T02:24:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 02:24:28 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-09-24 02:24:15 +0000 (Fri, 24 Sep 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for OpenEXR (EulerOS-SA-2021-2477)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2477" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2477" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'OpenEXR' package(s) announced via the EulerOS-SA-2021-2477 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in OpenEXR's Multipart input file functionality. A crafted multi-part input file with no actual parts can trigger a NULL pointer dereference. The highest threat from this vulnerability is to system availability.(CVE-2021-20299)

A flaw was found in OpenEXR's hufDecode functionality. This flaw allows an attacker who can pass a crafted file to be processed by OpenEXR, to trigger an undefined right shift error. The highest threat from this vulnerability is to system availability.(CVE-2021-20304)

A flaw was found in OpenEXR's B44Compressor. This flaw allows an attacker who can submit a crafted file to be processed by OpenEXR, to exhaust all memory accessible to the application. The highest threat from this vulnerability is to system availability.(CVE-2021-20298)

There is a flaw in OpenEXR's dataWindowForTile function. An attacker who is able to submit a crafted file to be processed by OpenEXR could trigger an integer overflow, leading to an out-of-bounds write on the heap. The greatest impact of this flaw is to application availability, with some potential impact to data integrity as well.(CVE-2021-20303)" );
	script_tag( name: "affected", value: "'OpenEXR' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "OpenEXR-libs", rpm: "OpenEXR-libs~2.2.0~15.h2.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

