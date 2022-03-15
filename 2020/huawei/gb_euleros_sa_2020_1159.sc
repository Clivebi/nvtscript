if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1159" );
	script_cve_id( "CVE-2019-19221" );
	script_tag( name: "creation_date", value: "2020-02-25 13:57:37 +0000 (Tue, 25 Feb 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-20 02:15:00 +0000 (Fri, 20 Mar 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for libarchive (EulerOS-SA-2020-1159)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1159" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1159" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libarchive' package(s) announced via the EulerOS-SA-2020-1159 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Libarchive 3.4.0, archive_wstring_append_from_mbs in archive_string.c has an out-of-bounds read because of an incorrect mbrtowc or mbtowc call. For example, bsdtar crashes via a crafted archive.(CVE-2019-19221)" );
	script_tag( name: "affected", value: "'libarchive' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "bsdtar", rpm: "bsdtar~3.3.2~2.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive", rpm: "libarchive~3.3.2~2.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive-devel", rpm: "libarchive-devel~3.3.2~2.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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
