if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2319" );
	script_cve_id( "CVE-2021-20095" );
	script_tag( name: "creation_date", value: "2021-09-04 02:25:52 +0000 (Sat, 04 Sep 2021)" );
	script_version( "2021-09-04T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-09-04 02:25:52 +0000 (Sat, 04 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-09-04 02:25:38 +0000 (Sat, 04 Sep 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for babel (EulerOS-SA-2021-2319)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2319" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2319" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'babel' package(s) announced via the EulerOS-SA-2021-2319 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in python-babel. A path traversal vulnerability was found in how locale data files are checked and loaded within python-babel, allowing a local attacker to trick an application that uses python-babel to load a file outside of the intended locale directory. The highest threat from this vulnerability is to data confidentiality and integrity as well as service availability.(CVE-2021-20095)" );
	script_tag( name: "affected", value: "'babel' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "babel", rpm: "babel~0.9.6~8.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-babel", rpm: "python-babel~0.9.6~8.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

