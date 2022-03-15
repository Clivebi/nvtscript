if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131243" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "creation_date", value: "2016-02-25 09:28:26 +0200 (Thu, 25 Feb 2016)" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0082" );
	script_tag( name: "insight", value: "Updated libssh packages fix security vulnerability: libssh versions 0.1 and above have a bits/bytes confusion bug and generate an abnormally short ephemeral secret for the diffie-hellman-group1 and diffie-hellman-group14 key exchange methods. The resulting secret is 128 bits long, instead of the recommended sizes of 1024 and 2048 bits respectively. Both client and server are vulnerable, pre-authentication. This vulnerability could be exploited by an eavesdropper with enough resources to decrypt or intercept SSH sessions (CVE-2016-0739)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0082.html" );
	script_cve_id( "CVE-2016-0739" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0082" );
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
	if(( res = isrpmvuln( pkg: "libssh", rpm: "libssh~0.6.5~1.1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

