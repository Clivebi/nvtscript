if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131251" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "creation_date", value: "2016-03-03 14:39:20 +0200 (Thu, 03 Mar 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0085" );
	script_tag( name: "insight", value: "Updated postgresql packages fix security vulnerabilities: PostgreSQL 9.3.x before 9.3.11 and 9.4.x before 9.4.6 does not properly restrict access to unspecified custom configuration settings (GUCS) for PL/Java, which allows attackers to gain privileges via unspecified vectors (CVE-2016-0766). PostgreSQL 9.3.x before 9.3.11 and 9.4.x before 9.4.6 allows remote attackers to cause a denial of service (infinite loop or buffer overflow and crash) via a large Unicode character range in a regular expression (CVE-2016-0773)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0085.html" );
	script_cve_id( "CVE-2016-0766", "CVE-2016-0773" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0085" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(( res = isrpmvuln( pkg: "3", rpm: "3~9.3.11~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "4", rpm: "4~9.4.6~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

