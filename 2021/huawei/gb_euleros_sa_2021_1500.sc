if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1500" );
	script_cve_id( "CVE-2017-2587", "CVE-2017-5849" );
	script_tag( name: "creation_date", value: "2021-03-05 07:08:42 +0000 (Fri, 05 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for netpbm (EulerOS-SA-2021-1500)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.6\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1500" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1500" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'netpbm' package(s) announced via the EulerOS-SA-2021-1500 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A memory allocation vulnerability was found in netpbm before 10.61. A maliciously crafted SVG file could cause the application to crash.(CVE-2017-2587)

tiffttopnm in netpbm 10.47.63 does not properly use the libtiff TIFFRGBAImageGet function, which allows remote attackers to cause a denial of service (out-of-bounds read and write) via a crafted tiff image file, related to transposing width and height values.(CVE-2017-5849)" );
	script_tag( name: "affected", value: "'netpbm' package(s) on Huawei EulerOS Virtualization 3.0.6.6." );
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
if(release == "EULEROSVIRT-3.0.6.6"){
	if(!isnull( res = isrpmvuln( pkg: "netpbm", rpm: "netpbm~10.79.00~7.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "netpbm-devel", rpm: "netpbm-devel~10.79.00~7.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "netpbm-progs", rpm: "netpbm-progs~10.79.00~7.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
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

