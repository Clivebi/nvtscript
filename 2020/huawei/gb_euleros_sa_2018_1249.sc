if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1249" );
	script_cve_id( "CVE-2017-7890" );
	script_tag( name: "creation_date", value: "2020-01-23 11:18:57 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for php (EulerOS-SA-2018-1249)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1249" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1249" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'php' package(s) announced via the EulerOS-SA-2018-1249 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The GIF decoding function gdImageCreateFromGifCtx in gd_gif_in.c in the GD Graphics Library (aka libgd), as used in PHP before 5.6.31 and 7.x before 7.1.7, does not zero colorMap arrays before use. A specially crafted GIF image could use the uninitialized tables to read ~700 bytes from the top of the stack, potentially disclosing sensitive information.(CVE-2017-7890)" );
	script_tag( name: "affected", value: "'php' package(s) on Huawei EulerOS Virtualization 2.5.0." );
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
if(release == "EULEROSVIRT-2.5.0"){
	if(!isnull( res = isrpmvuln( pkg: "php", rpm: "php~5.4.16~42.h7", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-cli", rpm: "php-cli~5.4.16~42.h7", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-common", rpm: "php-common~5.4.16~42.h7", rls: "EULEROSVIRT-2.5.0" ) )){
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

