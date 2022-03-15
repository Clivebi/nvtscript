if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131257" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_tag( name: "creation_date", value: "2016-03-08 07:15:21 +0200 (Tue, 08 Mar 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0096" );
	script_tag( name: "insight", value: "Mark Striemer discovered that Django incorrectly handled user-supplied redirect URLs containing basic authentication credentials. A remote attacker could possibly use this issue to perform a cross-site scripting attack or a malicious redirect. (CVE-2016-2512) Sjoerd Job Postmus discovered that Django incorrectly handled timing when doing password hashing operations. A remote attacker could possibly use this issue to perform user enumeration. (CVE-2016-2513)" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0096.html" );
	script_cve_id( "CVE-2016-2512", "CVE-2016-2513" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0096" );
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
	if(( res = isrpmvuln( pkg: "python-django", rpm: "python-django~1.8.10~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

