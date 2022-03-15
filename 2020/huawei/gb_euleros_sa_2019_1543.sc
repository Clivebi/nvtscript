if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1543" );
	script_cve_id( "CVE-2014-3597", "CVE-2014-3669", "CVE-2014-4721", "CVE-2014-5120", "CVE-2014-8142", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2348", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3329", "CVE-2015-4022", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4643", "CVE-2015-6834", "CVE-2015-6835", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-8873" );
	script_tag( name: "creation_date", value: "2020-01-23 12:09:56 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for php (EulerOS-SA-2019-1543)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1543" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1543" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'php' package(s) announced via the EulerOS-SA-2019-1543 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaws was discovered in the way PHP performed object unserialization. Specially crafted input processed by the unserialize() function could cause a PHP application to crash or, possibly, execute arbitrary code.(CVE-2014-8142)

It was found that certain PHP functions did not properly handle file names containing a NULL character. A remote attacker could possibly use this flaw to make a PHP script access unexpected files and bypass intended file system access restrictions.(CVE-2015-4026)

A flaw was discovered in the way PHP performed object unserialization. Specially crafted input processed by the unserialize() function could cause a PHP application to crash or, possibly, execute arbitrary code.(CVE-2015-6834)

It was found that certain PHP functions did not properly handle file names containing a NULL character. A remote attacker could possibly use this flaw to make a PHP script access unexpected files and bypass intended file system access restrictions.(CVE-2015-4025)

An integer overflow flaw was found in the way custom objects were unserialized. Specially crafted input processed by the unserialize() function could cause a PHP application to crash.(CVE-2014-3669)

It was found that PHP move_uploaded_file() function did not properly handle file names with a NULL character. A remote attacker could possibly use this flaw to make a PHP script access unexpected files and bypass intended file system access restrictions.(CVE-2015-2348)

An integer overflow flaw leading to a heap-based buffer overflow was found in the way PHP's FTP extension parsed file listing FTP server responses. A malicious FTP server could use this flaw to cause a PHP application to crash or, possibly, execute arbitrary code.(CVE-2015-4022)

A flaw was discovered in the way PHP performed object unserialization. Specially crafted input processed by the unserialize() function could cause a PHP application to crash or, possibly, execute arbitrary code.(CVE-2015-6836)

A NULL pointer dereference flaw was found in the XSLTProcessor class in PHP. An attacker could use this flaw to cause a PHP application to crash if it performed Extensible Stylesheet Language (XSL) transformations using untrusted XSLT files and allowed the use of PHP functions to be used as XSLT functions within XSL stylesheets.(CVE-2015-6837)

It was found that PHP's gd extension did not properly handle file names with a null character. A remote attacker could possibly use this flaw to make a PHP application access unexpected files and bypass intended file system access restrictions.(CVE-2014-5120)

A flaw was discovered in the way PHP performed object unserialization. Specially crafted input processed by the unserialize() function could cause a PHP application to crash or, possibly, execute arbitrary code.(CVE-2015-6835)

Stack consumption vulnerability in Zend/zend_exceptions.c in PHP before 5.4.44, 5.5.x before 5.5.28, and 5.6.x before ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'php' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "php", rpm: "php~5.4.16~45.h9", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-cli", rpm: "php-cli~5.4.16~45.h9", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-common", rpm: "php-common~5.4.16~45.h9", rls: "EULEROSVIRT-3.0.1.0" ) )){
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

