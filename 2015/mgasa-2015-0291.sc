if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130087" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 10:42:33 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0291" );
	script_tag( name: "insight", value: "The FreeRADIUS server relies on OpenSSL to perform certificate validation, including Certificate Revocation List (CRL) checks. The FreeRADIUS usage of OpenSSL, in CRL application, limits the checks to leaf certificates, therefore not detecting revocation of intermediate CA certificates. An unexpired client certificate, issued by an intermediate CA with a revoked certificate, is therefore accepted by FreeRADIUS (CVE-2015-4680). The freeradius package has been updated to version 2.2.8, which fixes this issue, as well as the failure to run on Mageia 5 due to an OpenSSL issue." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0291.html" );
	script_cve_id( "CVE-2015-4680" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0291" );
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
	if(( res = isrpmvuln( pkg: "freeradius", rpm: "freeradius~2.2.8~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

