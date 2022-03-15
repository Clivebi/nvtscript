if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131223" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-02-11 07:22:21 +0200 (Thu, 11 Feb 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0055" );
	script_tag( name: "insight", value: "This update fixes two denial-of-service vulnerabilities that have been discovered in privoxy 3.0.23: The remove_chunked_transfer_coding function in filters.c in Privoxy before 3.0.24 allows remote attackers to cause a denial of service (invalid read and crash) via crafted chunk-encoded content. (CVE-2016-1982) The client_host function in parsers.c in Privoxy before 3.0.24 allows remote attackers to cause a denial of service (invalid read and crash) via an empty HTTP Host header. (CVE-2016-1983)" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0055.html" );
	script_cve_id( "CVE-2016-1982", "CVE-2016-1983" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0055" );
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
	if(( res = isrpmvuln( pkg: "privoxy", rpm: "privoxy~3.0.23~1.1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

