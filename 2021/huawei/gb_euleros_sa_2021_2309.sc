if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2309" );
	script_cve_id( "CVE-2020-15389", "CVE-2020-27843" );
	script_tag( name: "creation_date", value: "2021-08-09 10:13:05 +0000 (Mon, 09 Aug 2021)" );
	script_version( "2021-08-09T11:38:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 11:38:50 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for openjpeg2 (EulerOS-SA-2021-2309)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2309" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2309" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'openjpeg2' package(s) announced via the EulerOS-SA-2021-2309 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a use-after-free that can be triggered if there is a mix of valid and invalid files in a directory operated on by the decompressor. Triggering a double-free may also be possible. This is related to calling opj_image_destroy twice.(CVE-2020-15389)

A flaw was found in OpenJPEG in versions prior to 2.4.0. This flaw allows an attacker to provide specially crafted input to the conversion or encoding functionality, causing an out-of-bounds read. The highest threat from this vulnerability is system availability.(CVE-2020-27843)" );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "openjpeg2", rpm: "openjpeg2~2.3.0~9.h9.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

