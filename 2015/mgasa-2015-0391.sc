if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130002" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 06:54:56 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0391" );
	script_tag( name: "insight", value: "Zend Framework contained several instances where it was using incorrect permissions masks, which could lead to local privilege escalation issues (CVE-2015-5723). The PDO adapters of Zend Framework 1 do not filter null bytes values in SQL statements. A PDO adapter can treat null bytes in a query as a string terminator, allowing an attacker to add arbitrary SQL following a null byte, and thus create a SQL injection (ZF2015-08). Note that the ZF2015-08 issue did not affect Zend Framework 2." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0391.html" );
	script_cve_id( "CVE-2015-5723" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0391" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Mageia Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MAGEIA5"){
	if(( res = isrpmvuln( pkg: "php-ZendFramework", rpm: "php-ZendFramework~1.12.16~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-ZendFramework2", rpm: "php-ZendFramework2~2.4.8~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
