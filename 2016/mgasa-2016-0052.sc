if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131208" );
	script_version( "2021-02-05T10:24:35+0000" );
	script_tag( name: "creation_date", value: "2016-02-08 19:55:15 +0200 (Mon, 08 Feb 2016)" );
	script_tag( name: "last_modification", value: "2021-02-05 10:24:35 +0000 (Fri, 05 Feb 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0052" );
	script_tag( name: "insight", value: "In all versions of MIT krb5, an authenticated attacker can cause kadmind to read beyond the end of allocated memory by sending a string without a terminating zero byte. Information leakage may be possible for an attacker with permission to modify the database (CVE-2015-8629). In MIT krb5 1.12 and later, an authenticated attacker with permission to modify a principal entry can cause kadmind to dereference a null pointer by supplying a null policy value but including KADM5_POLICY in the mask (CVE-2015-8630). In all versions of MIT krb5, an authenticated attacker can cause kadmind to leak memory by supplying a null principal name in a request which uses one. Repeating these requests will eventually cause kadmind to exhaust all available memory (CVE-2015-8631)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0052.html" );
	script_cve_id( "CVE-2015-8629", "CVE-2015-8630", "CVE-2015-8631" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0052" );
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
	if(( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.12.2~8.3.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

