if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2710" );
	script_cve_id( "CVE-2017-11683", "CVE-2017-14859", "CVE-2017-14862", "CVE-2017-14864", "CVE-2017-14865", "CVE-2017-17669", "CVE-2017-18005", "CVE-2018-16336", "CVE-2018-4868", "CVE-2019-14982" );
	script_tag( name: "creation_date", value: "2020-01-23 13:15:03 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for exiv2 (EulerOS-SA-2019-2710)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2710" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2710" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'exiv2' package(s) announced via the EulerOS-SA-2019-2710 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Exiv2::Internal::PngChunk::parseTXTChunk in Exiv2 v0.26 allows remote attackers to cause a denial of service (heap-based buffer over-read) via a crafted image file, a different vulnerability than CVE-2018-10999.(CVE-2018-16336)

The Exiv2::Jp2Image::readMetadata function in jp2image.cpp in Exiv2 0.26 allows remote attackers to cause a denial of service (excessive memory allocation) via a crafted file.(CVE-2018-4868)

In Exiv2 before v0.27.2, there is an integer overflow vulnerability in the WebPImage::getHeaderOffset function in webpimage.cpp. It can lead to a buffer overflow vulnerability and a crash.(CVE-2019-14982)

There is a reachable assertion in the Internal::TiffReader::visitDirectory function in tiffvisitor.cpp of Exiv2 0.26 that will lead to a remote denial of service attack via crafted input.(CVE-2017-11683)

An Invalid memory address dereference was discovered in Exiv2::StringValueBase::read in value.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.(CVE-2017-14859)

An Invalid memory address dereference was discovered in Exiv2::DataValue::read in value.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.(CVE-2017-14862)

An Invalid memory address dereference was discovered in Exiv2::getULong in types.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.(CVE-2017-14864)

There is a heap-based buffer overflow in the Exiv2::us2Data function of types.cpp in Exiv2 0.26. A Crafted input will lead to a denial of service attack.(CVE-2017-14865)

There is a heap-based buffer over-read in the Exiv2::Internal::PngChunk::keyTXTChunk function of pngchunk_int.cpp in Exiv2 0.26. A crafted PNG file will lead to a remote denial of service attack.(CVE-2017-17669)

Exiv2 0.26 has a Null Pointer Dereference in the Exiv2::DataValue::toLong function in value.cpp, related to crafted metadata in a TIFF file.(CVE-2017-18005)" );
	script_tag( name: "affected", value: "'exiv2' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "exiv2-libs", rpm: "exiv2-libs~0.26~3.h10.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

