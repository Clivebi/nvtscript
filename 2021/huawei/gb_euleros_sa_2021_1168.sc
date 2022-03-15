if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1168" );
	script_cve_id( "CVE-2020-14343" );
	script_tag( name: "creation_date", value: "2021-02-02 07:45:12 +0000 (Tue, 02 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-16 16:22:00 +0000 (Tue, 16 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for PyYAML (EulerOS-SA-2021-1168)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1168" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1168" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'PyYAML' package(s) announced via the EulerOS-SA-2021-1168 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "YAML is a data serialization format designed for human readability andinteraction with scripting languages. PyYAML is a YAML parser andemitter for Python.PyYAML features a complete YAML 1.1 complete YAML 1.1 parser, Unicode support, picklesupport, capable extension API, and sensible error messages. PyYAML supports(CVE-2020-14343)" );
	script_tag( name: "affected", value: "'PyYAML' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "PyYAML", rpm: "PyYAML~4.2~0.1.b4.h5.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-pyyaml", rpm: "python2-pyyaml~4.2~0.1.b4.h5.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-pyyaml", rpm: "python3-pyyaml~4.2~0.1.b4.h5.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

