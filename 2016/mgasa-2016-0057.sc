if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131221" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "creation_date", value: "2016-02-11 07:22:20 +0200 (Thu, 11 Feb 2016)" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0057" );
	script_tag( name: "insight", value: "Updated radicale package fixes security vulnerabilities: If an attacker is able to authenticate with a user name like `.*', he can bypass read/write limitations imposed by regex-based rules, including the built-in rules `owner_write' (read for everybody, write for the calendar owner) and `owner_only' (read and write for the calendar owner) (CVE-2015-8748). The radicale package has been updated to version 1.1.1, fixing this issue and several other security issues." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0057.html" );
	script_cve_id( "CVE-2015-8748" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0057" );
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
	if(( res = isrpmvuln( pkg: "radicale", rpm: "radicale~1.1.1~1.1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

