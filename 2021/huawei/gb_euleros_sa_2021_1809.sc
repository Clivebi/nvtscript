if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1809" );
	script_cve_id( "CVE-2020-0182", "CVE-2020-0452" );
	script_tag( name: "creation_date", value: "2021-05-03 06:21:53 +0000 (Mon, 03 May 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-25 04:15:00 +0000 (Wed, 25 Nov 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for libexif (EulerOS-SA-2021-1809)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1809" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1809" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libexif' package(s) announced via the EulerOS-SA-2021-1809 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In exif_entry_get_value of exif-entry.c, there is a possible out of bounds read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-147140917(CVE-2020-0182)

In exif_entry_get_value of exif-entry.c, there is a possible out of bounds write due to an integer overflow. This could lead to remote code execution if a third party app used this library to process remote image data with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11 Android-8.0Android ID: A-159625731(CVE-2020-0452)" );
	script_tag( name: "affected", value: "'libexif' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libexif", rpm: "libexif~0.6.21~6.h7", rls: "EULEROS-2.0SP3" ) )){
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

