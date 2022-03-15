if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2302" );
	script_cve_id( "CVE-2013-4420" );
	script_tag( name: "creation_date", value: "2021-08-09 10:12:55 +0000 (Mon, 09 Aug 2021)" );
	script_version( "2021-08-09T11:38:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 11:38:50 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2014-02-20 23:51:00 +0000 (Thu, 20 Feb 2014)" );
	script_name( "Huawei EulerOS: Security Advisory for libtar (EulerOS-SA-2021-2302)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2302" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2302" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libtar' package(s) announced via the EulerOS-SA-2021-2302 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple directory traversal vulnerabilities in the (1) tar_extract_glob and (2) tar_extract_all functions in libtar 1.2.20 and earlier allow remote attackers to overwrite arbitrary files via a .. (dot dot) in a crafted tar file.(CVE-2013-4420)" );
	script_tag( name: "affected", value: "'libtar' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtar", rpm: "libtar~1.2.20~15.h1.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

