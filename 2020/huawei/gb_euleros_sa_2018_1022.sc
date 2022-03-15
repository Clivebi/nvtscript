if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1022" );
	script_cve_id( "CVE-2017-17784", "CVE-2017-17785", "CVE-2017-17786", "CVE-2017-17787", "CVE-2017-17788", "CVE-2017-17789" );
	script_tag( name: "creation_date", value: "2020-01-23 11:08:23 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 18:25:00 +0000 (Wed, 13 Mar 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for gimp (EulerOS-SA-2018-1022)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1022" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1022" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'gimp' package(s) announced via the EulerOS-SA-2018-1022 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In GIMP 2.8.22, there is a heap-based buffer over-read in load_image in plug-ins/common/file-gbr.c in the gbr import parser, related to mishandling of UTF-8 data.(CVE-2017-17784)

In GIMP 2.8.22, there is a heap-based buffer overflow in the fli_read_brun function in plug-ins/file-fli/fli.c.(CVE-2017-17785)

In GIMP 2.8.22, there is a heap-based buffer over-read in ReadImage in plug-ins/common/file-tga.c (related to bgr2rgb.part.1) via an unexpected bits-per-pixel value for an RGBA image.(CVE-2017-17786)

In GIMP 2.8.22, there is a heap-based buffer over-read in read_creator_block in plug-ins/common/file-psp.c.(CVE-2017-1778)

In GIMP 2.8.22, there is a stack-based buffer over-read in xcf_load_stream in app/xcf/xcf.c when there is no '\\\\0' character after the version string.(CVE-2017-17788)

In GIMP 2.8.22, there is a heap-based buffer overflow in read_channel_data in plug-ins/common/file-psp.c.(CVE-2017-17789)" );
	script_tag( name: "affected", value: "'gimp' package(s) on Huawei EulerOS V2.0SP1." );
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
if(release == "EULEROS-2.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "gimp", rpm: "gimp~2.8.10~3.h7", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-libs", rpm: "gimp-libs~2.8.10~3.h7", rls: "EULEROS-2.0SP1" ) )){
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

