if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2414" );
	script_cve_id( "CVE-2018-16375", "CVE-2020-27823", "CVE-2020-27824" );
	script_tag( name: "creation_date", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_version( "2021-09-15T02:24:22+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-26 12:50:00 +0000 (Tue, 26 Jan 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for openjpeg (EulerOS-SA-2021-2414)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2414" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2414" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'openjpeg' package(s) announced via the EulerOS-SA-2021-2414 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in OpenJPEG's encoder. This flaw allows an attacker to pass specially crafted x,y offset input to OpenJPEG to use during encoding. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2020-27823)

A flaw was found in OpenJPEG's encoder in the opj_dwt_calc_explicit_stepsizes() function. This flaw allows an attacker who can supply crafted input to decomposition levels to cause a buffer overflow. The highest threat from this vulnerability is to system availability.(CVE-2020-27824)

An issue was discovered in OpenJPEG 2.3.0. Missing checks for header_info.height and header_info.width in the function pnmtoimage in bin/jpwl/convert.c can lead to a heap-based buffer overflow.(CVE-2018-16375)" );
	script_tag( name: "affected", value: "'openjpeg' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "openjpeg-libs", rpm: "openjpeg-libs~1.5.1~16.h8", rls: "EULEROS-2.0SP2" ) )){
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

