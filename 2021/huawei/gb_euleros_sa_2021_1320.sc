if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1320" );
	script_cve_id( "CVE-2016-9297", "CVE-2016-9448", "CVE-2017-11335", "CVE-2017-9404" );
	script_tag( name: "creation_date", value: "2021-02-22 08:38:14 +0000 (Mon, 22 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-22 01:29:00 +0000 (Thu, 22 Mar 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2021-1320)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1320" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1320" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libtiff' package(s) announced via the EulerOS-SA-2021-1320 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The TIFFFetchNormalTag function in LibTiff 4.0.6 allows remote attackers to cause a denial of service (out-of-bounds read) via crafted TIFF_SETGET_C16ASCII or TIFF_SETGET_C32_ASCII tag values.(CVE-2016-9297)

The TIFFFetchNormalTag function in LibTiff 4.0.6 allows remote attackers to cause a denial of service (NULL pointer dereference and crash) by setting the tags TIFF_SETGET_C16ASCII or TIFF_SETGET_C32_ASCII to values that access 0-byte arrays. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-9297.(CVE-2016-9448)

In LibTIFF 4.0.7, a memory leak vulnerability was found in the function OJPEGReadHeaderInfoSecTablesQTable in tif_ojpeg.c, which allows attackers to cause a denial of service via a crafted file.(CVE-2017-9404)

There is a heap based buffer overflow in tools/tiff2pdf.c of LibTIFF 4.0.8 via a PlanarConfig=Contig image, which causes a more than one hundred bytes out-of-bounds write (related to the ZIPDecode function in tif_zip.c). A crafted input may lead to a remote denial of service attack or an arbitrary code execution attack.(CVE-2017-11335)" );
	script_tag( name: "affected", value: "'libtiff' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~4.0.3~27.h20", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~4.0.3~27.h20", rls: "EULEROS-2.0SP2" ) )){
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

