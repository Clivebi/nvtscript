if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2016.1029" );
	script_cve_id( "CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2016-5118", "CVE-2016-5239", "CVE-2016-5240" );
	script_tag( name: "creation_date", value: "2020-01-23 10:38:56 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for ImageMagick (EulerOS-SA-2016-1029)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2016-1029" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1029" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ImageMagick' package(s) announced via the EulerOS-SA-2016-1029 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that ImageMagick did not properly sanitize certain input before using it to invoke processes. A remote attacker could create a specially crafted image that, when processed by an application using ImageMagick or an unsuspecting user using the ImageMagick utilities, would lead to arbitrary execution of shell commands with the privileges of the user running the application.(CVE-2016-5118)

It was discovered that ImageMagick did not properly sanitize certain input before passing it to the gnuplot delegate functionality. A remote attacker could create a specially crafted image that, when processed by an application using ImageMagick or an unsuspecting user using the ImageMagick utilities, would lead to arbitrary execution of shell commands with the privileges of the user running the application. (CVE-2016-5239)

Multiple flaws have been discovered in ImageMagick. A remote attacker could, for example, create specially crafted images that, when processed by an application using ImageMagick or an unsuspecting user using the ImageMagick utilities, would result in a memory corruption and, potentially, execution of arbitrary code, a denial of service, or an application crash. (CVE-2015-8896, CVE-2015-8895, CVE-2016-5240, CVE-2015-8897, CVE-2015-8898)" );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on Huawei EulerOS V2.0SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~6.7.8.9~15", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-c++", rpm: "ImageMagick-c++~6.7.8.9~15", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-perl", rpm: "ImageMagick-perl~6.7.8.9~15", rls: "EULEROS-2.0SP1" ) )){
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

