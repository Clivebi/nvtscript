if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131144" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-12-08 11:03:38 +0200 (Tue, 08 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0466" );
	script_tag( name: "insight", value: "If a client receives a ServerKeyExchange for an anonymous DH ciphersuite with the value of p set to 0 then a seg fault can occur leading to a possible denial of service attack (CVE-2015-1794). Loic Jonas Etienne of Qnective AG discovered that the signature verification routines will crash with a NULL pointer dereference if presented with an ASN.1 signature using the RSA PSS algorithm and absent mask generation function parameter. A remote attacker can exploit this flaw to crash any certificate verification operation and mount a denial of service attack (CVE-2015-3194). Adam Langley of Google/BoringSSL discovered that OpenSSL will leak memory when presented with a malformed X509_ATTRIBUTE structure (CVE-2015-3195). A race condition flaw in the handling of PSK identify hints was discovered, potentially leading to a double free of the identify hint data (CVE-2015-3196)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0466.html" );
	script_cve_id( "CVE-2015-1794", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0466" );
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
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.2e~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

