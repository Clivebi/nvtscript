if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1275" );
	script_cve_id( "CVE-2017-14226" );
	script_tag( name: "creation_date", value: "2020-01-23 11:02:55 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 21:46:00 +0000 (Mon, 09 Nov 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for libwpd (EulerOS-SA-2017-1275)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1275" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1275" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libwpd' package(s) announced via the EulerOS-SA-2017-1275 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "WP1StylesListener.cpp, WP5StylesListener.cpp, and WP42StylesListener.cpp in libwpd 0.10.1 mishandle iterators, which allows remote attackers to cause a denial of service (heap-based buffer over-read in the WPXTableList class in WPXTable.cpp). This vulnerability can be triggered in LibreOffice before 5.3.7. It may lead to suffering a remote attack against a LibreOffice application.(CVE-2017-14226)" );
	script_tag( name: "affected", value: "'libwpd' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libwpd", rpm: "libwpd~0.10.0~1.h1", rls: "EULEROS-2.0SP2" ) )){
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

